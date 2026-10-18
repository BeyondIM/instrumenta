package instrumenta

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
)

const maxErrorMsgBodyLen = 512 // 错误信息中内嵌响应体的最大长度，防止巨型 HTML 报错页撑爆日志

var (
	transportCache sync.Map // Key: 网络配置哈希 -> Value: *http.Transport
	sfGroup        singleflight.Group
)

type HTTPError struct {
	StatusCode int
	Body       []byte
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("HTTP request failed with status code %d", e.StatusCode)
}

type HttpHeadParams struct {
	Header http.Header
	Host   string
	Url    string
}

type HttpHeadResp struct {
	StatusCode int
	Location   string
	RespHeader http.Header
}

type HttpGetParams struct {
	Header       http.Header
	Host         string
	Url          string
	SearchParams map[string]string
}

type HttpGetResp struct {
	Body       []byte
	Location   string
	StatusCode int
	RespHeader http.Header
	Cookies    []*http.Cookie
}

type HttpPostParams struct {
	Body     interface{}
	Header   http.Header
	Host     string
	PostType string
	Url      string
}

type HttpPostResp struct {
	StatusCode int
	Body       []byte
	RespHeader http.Header
	Cookies    []*http.Cookie
}

type HttpPutParams struct {
	Body   interface{}
	Header http.Header
	Host   string
	Url    string
}

type HttpPatchParams struct {
	Body   interface{}
	Header http.Header
	Host   string
	Url    string
}

type HttpDeleteParams struct {
	Body   interface{}
	Header http.Header
	Host   string
	Url    string
}

type UpstreamErr struct {
	Error string `json:"error"`
}

type clientBuilder struct {
	timeout               time.Duration
	responseHeaderTimeout time.Duration
	skipInsecure          bool
	caCert                string
	proxyURL              string
	randomProxy           bool
	sharedJar             http.CookieJar
}

type ClientOption func(*clientBuilder)

type CookieDeduplicateTransport struct {
	Transport http.RoundTripper
}

type cookieEntry struct {
	key   string
	val   string
	hasEq bool
}

// isHexBytes 检查字符串是否全为十六进制字符
func isHexBytes(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isDynamicHexLen 判断长度是否为常见的随机 Hex 长度（避免创建 map 产生堆内存分配）
func isDynamicHexLen(n int) bool {
	switch n {
	case 8, 16, 32, 40, 64:
		return true
	default:
		return false
	}
}

// classifyCookie 判断 Cookie Key 的类型并生成独立的归类组标识：
// 返回值: (是否为动态垃圾Cookie, 归类组标识)
// - 普通业务 Cookie (如 "bbs_sid"): 返回 (false, "")
// - 16位纯随机 Hex Key: 返回 (true, "__PURE_HEX_16__")
// - 32位纯随机 Hex Key: 返回 (true, "__PURE_HEX_32__")
// - 带前缀的随机 Hex Key (如 "server_session_60bd140e"): 返回 (true, "prefix:server_session_8")
func classifyCookie(k string) (bool, string) {
	// 情况 A：key 本身就是纯 8/16/32/40/64 位 Hex 串
	// 按不同长度分别生成 groupKey，确保 16 位和 32 位各自独立保留最后一个
	if isDynamicHexLen(len(k)) && isHexBytes(k) {
		return true, "__PURE_HEX_" + strconv.Itoa(len(k)) + "__"
	}

	// 情况 B：key 带下划线前缀，且最后一个下划线后的后缀是 8/16/32/40/64 位 Hex 串
	if idx := strings.LastIndex(k, "_"); idx != -1 {
		suffix := k[idx+1:]
		if isDynamicHexLen(len(suffix)) && isHexBytes(suffix) {
			return true, "prefix:" + k[:idx+1] + strconv.Itoa(len(suffix))
		}
	}

	return false, ""
}

func (t *CookieDeduplicateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}

	// 记录本次请求中被判定为“已被淘汰的旧动态 Cookie 名称”，用于在响应返回时通知 CookieJar 删除它们
	var evictedKeys []string

	cookieHeaders := req.Header.Values("Cookie")
	if len(cookieHeaders) > 0 {
		seen := make(map[string]int)
		dynamicGroupIdx := make(map[string]int) // groupKey -> entries index
		var entries []cookieEntry
		needRewrite := len(cookieHeaders) > 1

		for _, cookieStr := range cookieHeaders {
			parts := strings.Split(cookieStr, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
					if k == "" {
						continue
					}

					// 1. 检查是否为动态生成的 Hex Cookie（纯 Hex 或带前缀 Hex）
					if isDyn, groupKey := classifyCookie(k); isDyn {
						needRewrite = true
						if gIdx, exists := dynamicGroupIdx[groupKey]; exists {
							// 存在同组旧的动态 Cookie：记录旧 key 以便稍后从 Jar 中物理清除，并用新 key 覆盖槽位
							oldKey := entries[gIdx].key
							if oldKey != k {
								evictedKeys = append(evictedKeys, oldKey)
							}
							entries[gIdx] = cookieEntry{key: k, val: v, hasEq: true}
							seen[k] = gIdx
						} else {
							dynamicGroupIdx[groupKey] = len(entries)
							seen[k] = len(entries)
							entries = append(entries, cookieEntry{key: k, val: v, hasEq: true})
						}
						continue
					}

					// 2. 正常业务 Cookie：同名后面覆盖前面
					if idx, exists := seen[k]; exists {
						entries[idx].val = v
						entries[idx].hasEq = true
						needRewrite = true
					} else {
						seen[k] = len(entries)
						entries = append(entries, cookieEntry{key: k, val: v, hasEq: true})
					}
				} else {
					k := part
					if idx, exists := seen[k]; exists {
						entries[idx] = cookieEntry{key: k, hasEq: false}
						needRewrite = true
					} else {
						seen[k] = len(entries)
						entries = append(entries, cookieEntry{key: k, hasEq: false})
					}
				}
			}
		}

		if needRewrite {
			reqCopy := req.Clone(req.Context())
			if len(entries) > 0 {
				cleanCookies := make([]string, len(entries))
				for i, e := range entries {
					if e.hasEq {
						cleanCookies[i] = e.key + "=" + e.val
					} else {
						cleanCookies[i] = e.key
					}
				}
				reqCopy.Header.Set("Cookie", strings.Join(cleanCookies, "; "))
			} else {
				reqCopy.Header.Del("Cookie")
			}
			req = reqCopy
		}
	}

	res, err := rt.RoundTrip(req)
	if err != nil || res == nil {
		return res, err
	}

	// 如果存在被淘汰的旧动态 Cookie，在响应头中追加 Max-Age=0 过期指令，
	// 这样当 RoundTrip 返回后，http.Client 会自动将它们从 client.Jar 中永久删除！
	if len(evictedKeys) > 0 {
		if res.Header == nil {
			res.Header = make(http.Header)
		}
		for _, oldKey := range evictedKeys {
			res.Header.Add("Set-Cookie", oldKey+"=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
		}
	}

	return res, nil
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(b *clientBuilder) {
		b.timeout = timeout
	}
}

func WithResponseHeaderTimeout(responseHeaderTimeout time.Duration) ClientOption {
	return func(b *clientBuilder) {
		b.responseHeaderTimeout = responseHeaderTimeout
	}
}

func WithInsecureSkipVerify() ClientOption {
	return func(b *clientBuilder) {
		b.skipInsecure = true
	}
}

func WithCACert(cert string) ClientOption {
	return func(b *clientBuilder) {
		b.caCert = cert
	}
}

func WithFixedProxy(proxyURL string) ClientOption {
	return func(b *clientBuilder) {
		b.proxyURL = proxyURL
		b.randomProxy = false
	}
}

func WithRandomProxy(proxyURL string) ClientOption {
	return func(b *clientBuilder) {
		b.proxyURL = proxyURL
		b.randomProxy = true
	}
}

func WithSharedJar(jar http.CookieJar) ClientOption {
	return func(b *clientBuilder) {
		b.sharedJar = jar
	}
}

func (b *clientBuilder) transportKey() string {
	h := fnv.New64a()
	// 带长度前缀的格式化，彻底消除字符串内容包含分隔符引发的哈希碰撞
	fmt.Fprintf(h, "%d|%t|%d:%s|%d:%s|%t",
		b.responseHeaderTimeout,
		b.skipInsecure,
		len(b.caCert), b.caCert,
		len(b.proxyURL), b.proxyURL,
		b.randomProxy,
	)
	return strconv.FormatUint(h.Sum64(), 16)
}

func (b *clientBuilder) getOrBuildTransport() (*http.Transport, error) {
	tKey := b.transportKey()

	// 快速路径 (Fast Path)
	if t, ok := transportCache.Load(tKey); ok {
		return t.(*http.Transport), nil
	}

	// 慢速路径 (Slow Path)：防止缓存击穿
	v, err, _ := sfGroup.Do(tKey, func() (interface{}, error) {
		if t, ok := transportCache.Load(tKey); ok {
			return t, nil
		}

		baseDialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		transport := &http.Transport{
			ForceAttemptHTTP2:     true,
			ResponseHeaderTimeout: b.responseHeaderTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			IdleConnTimeout:       120 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			MaxConnsPerHost:       50,
		}

		// 处理随机代理模式：彻底禁用连接池与 TCP KeepAlive
		if b.randomProxy {
			baseDialer.KeepAlive = -1
			transport.DisableKeepAlives = true
			transport.MaxIdleConnsPerHost = -1
			transport.MaxIdleConns = 0
			transport.IdleConnTimeout = 0
		}

		// 代理路由与底层连接策略
		if b.proxyURL != "" {
			proxyURL, err := url.Parse(b.proxyURL)
			if err != nil || proxyURL.Host == "" {
				return nil, fmt.Errorf("invalid proxy URL %q: missing host or malformed", b.proxyURL)
			}

			scheme := strings.ToLower(proxyURL.Scheme)
			switch scheme {
			case "socks5", "socks5h":
				// golang.org/x/net/proxy 默认只注册了 "socks5"（且其底层默认即支持远端 DNS 解析，等同于 socks5h）
				normalizedURL := *proxyURL
				normalizedURL.Scheme = "socks5"

				socksDialer, err := proxy.FromURL(&normalizedURL, baseDialer)
				if err != nil {
					return nil, fmt.Errorf("failed to create socks proxy dialer: %w", err)
				}

				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					if contextDialer, ok := socksDialer.(proxy.ContextDialer); ok {
						return contextDialer.DialContext(ctx, network, addr)
					}

					dialCtx, cancel := context.WithTimeout(ctx, baseDialer.Timeout)
					defer cancel()

					type result struct {
						conn net.Conn
						err  error
					}
					resultCh := make(chan result, 1)

					go func() {
						conn, err := socksDialer.Dial(network, addr)
						if dialCtx.Err() != nil {
							if conn != nil {
								_ = conn.Close()
							}
							return
						}
						resultCh <- result{conn, err}
					}()

					select {
					case <-dialCtx.Done():
						return nil, dialCtx.Err()
					case res := <-resultCh:
						return res.conn, res.err
					}
				}
			case "http", "https":
				transport.Proxy = http.ProxyURL(proxyURL)
				transport.DialContext = baseDialer.DialContext
			default:
				return nil, fmt.Errorf("unsupported proxy scheme in URL: %s", b.proxyURL)
			}
		} else {
			transport.DialContext = baseDialer.DialContext
		}

		// --- TLS 配置 ---
		if b.skipInsecure || b.caCert != "" {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: b.skipInsecure,
				MinVersion:         tls.VersionTLS12,
				// 显式声明 ALPN 协议列表，防止自定义 DialContext + TLSConfig 下 HTTP/2 协商失效
				NextProtos: []string{"h2", "http/1.1"},
			}
			if b.caCert != "" {
				// 优先继承系统默认根证书池，避免配置自定义 CA 后无法访问常规公网 HTTPS
				caCertPool, err := x509.SystemCertPool()
				if err != nil || caCertPool == nil {
					caCertPool = x509.NewCertPool()
				}
				if !caCertPool.AppendCertsFromPEM([]byte(b.caCert)) {
					certData, err := os.ReadFile(b.caCert)
					if err != nil || !caCertPool.AppendCertsFromPEM(certData) {
						return nil, fmt.Errorf("failed to parse CA certificate from string or file")
					}
				}
				tlsConfig.RootCAs = caCertPool
			}
			transport.TLSClientConfig = tlsConfig
		}

		transportCache.Store(tKey, transport)
		return transport, nil
	})

	if err != nil {
		return nil, err
	}
	return v.(*http.Transport), nil
}

func GetClient(opts ...ClientOption) (*http.Client, error) {
	builder := &clientBuilder{
		timeout:               60 * time.Second,
		responseHeaderTimeout: 15 * time.Second,
		randomProxy:           false,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(builder)
		}
	}

	sharedTransport, err := builder.getOrBuildTransport()
	if err != nil {
		return nil, fmt.Errorf("failed to build transport: %w", err)
	}

	client := &http.Client{
		Transport: &CookieDeduplicateTransport{Transport: sharedTransport},
		Timeout:   builder.timeout,
		Jar:       builder.sharedJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return client, nil
}

// WithJar 从已有 client 衍生出一个挂载新 CookieJar 的客户端副本。
// 该副本与原 client 共享底层的网络 Transport 和长连接池，但拥有独立的 Cookie 会话状态。
func WithJar(client *http.Client, jar http.CookieJar) *http.Client {
  if client == nil {
    return nil
  }
  cloned := *client
  cloned.Jar = jar
  return &cloned
}

// isNilPayload 判断 interface{} 是否为 nil 或值为 nil 的指针/接口
func isNilPayload(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Ptr:
		return rv.IsNil()
	default:
		return false
	}
}

// marshalJSONBody 智能序列化：兼容调用方直接传入 []byte / string / json.RawMessage，避免被二次 Base64 编码
func marshalJSONBody(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case []byte:
		return val, nil
	case json.RawMessage:
		return val, nil
	case string:
		return []byte(val), nil
	default:
		return sonic.Marshal(v)
	}
}

// ensureContext 防止调用方传入 nil context 导致 http.NewRequestWithContext 触发 panic
func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// applyRequestMeta 克隆 Header 并设置 Host 与 Content-Type
func applyRequestMeta(req *http.Request, header http.Header, host, contentType string, forceContentType bool) {
	if header != nil {
		req.Header = header.Clone()
	} else {
		req.Header = make(http.Header)
	}
	if contentType != "" {
		if forceContentType || req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", contentType)
		}
	}
	if len(host) > 0 {
		req.Host = host
		req.Header.Del("Host")
	} else if hdrHost := req.Header.Get("Host"); hdrHost != "" {
		// 兼容调用方在 Header 中设置 Host 的习惯（Go 标准库默认忽略 req.Header["Host"]）
		req.Host = hdrHost
		req.Header.Del("Host")
	}
}

// resolveLocation 解析响应的最终 URL：
// 1. 若响应停留在 3xx 状态（如达到最大重定向次数触发 ErrUseLastResponse），提取并解析 Location 响应头；
// 2. 若响应为 2xx（即使带有 Location 头，如 201 Created），返回当前请求实际落地的 URL。
func resolveLocation(res *http.Response, fallbackURL string) string {
	if res == nil {
		return fallbackURL
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		if loc := res.Header.Get("Location"); loc != "" {
			if res.Request != nil && res.Request.URL != nil {
				if resolved, err := res.Request.URL.Parse(loc); err == nil {
					return resolved.String()
				}
			}
			return loc
		}
	}
	if res.Request != nil && res.Request.URL != nil {
		return res.Request.URL.String()
	}
	return fallbackURL
}

// extractCookies 提取响应中的 Cookie，并折叠动态垃圾 Cookie（每种动态类型只保留最新 1 个）
func extractCookies(client *http.Client, res *http.Response, rawURL string) []*http.Cookie {
	var rawCookies []*http.Cookie
	if client != nil && client.Jar != nil {
		if res.Request != nil && res.Request.URL != nil {
			rawCookies = client.Jar.Cookies(res.Request.URL)
		} else if u, err := url.Parse(rawURL); err == nil {
			rawCookies = client.Jar.Cookies(u)
		}
	} else if res != nil {
		rawCookies = res.Cookies()
	}

	if len(rawCookies) == 0 {
		return rawCookies
	}

	// 对提取出的 Cookie 列表执行同样的去重与动态折叠，确保返回给调用方的列表永远干净
	seen := make(map[string]int)
	dynamicGroupIdx := make(map[string]int)
	result := make([]*http.Cookie, 0, len(rawCookies))

	for _, c := range rawCookies {
		if c == nil || c.Name == "" {
			continue
		}
		if isDyn, groupKey := classifyCookie(c.Name); isDyn {
			if gIdx, exists := dynamicGroupIdx[groupKey]; exists {
				result[gIdx] = c // 同类动态 Cookie，用后面的（更新的）覆盖前面的
			} else {
				dynamicGroupIdx[groupKey] = len(result)
				result = append(result, c)
			}
			continue
		}

		if idx, exists := seen[c.Name]; exists {
			result[idx] = c
		} else {
			seen[c.Name] = len(result)
			result = append(result, c)
		}
	}

	return result
}

// checkStatusError 统一校验 HTTP 状态码（允许 2xx 和 ErrUseLastResponse 产生的 3xx）
func checkStatusError(statusCode int, bodyBytes []byte) error {
	if statusCode >= 200 && statusCode < 400 {
		return nil
	}
	var upstreamErr UpstreamErr
	if len(bodyBytes) > 0 {
		_ = sonic.Unmarshal(bodyBytes, &upstreamErr)
	}

	errMsg := upstreamErr.Error
	if errMsg == "" {
		if len(bodyBytes) > 0 {
			preview := bodyBytes
			suffix := ""
			if len(preview) > maxErrorMsgBodyLen {
				preview = preview[:maxErrorMsgBodyLen]
				suffix = "...(truncated)"
			}
			errMsg = fmt.Sprintf("Upstream error (status %d): %s%s", statusCode, string(preview), suffix)
		} else {
			errMsg = fmt.Sprintf("Upstream error (status %d)", statusCode)
		}
	}
	return &HTTPError{
		StatusCode: statusCode,
		Body:       bodyBytes,
		Message:    errMsg,
	}
}

func HttpHead(ctx context.Context, client *http.Client, p *HttpHeadParams) (*HttpHeadResp, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	req, err := http.NewRequestWithContext(ensureContext(ctx), http.MethodHead, p.Url, nil)
	if err != nil {
		return nil, err
	}
	applyRequestMeta(req, p.Header, p.Host, "", false)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if err := checkStatusError(res.StatusCode, nil); err != nil {
		return nil, err
	}

	return &HttpHeadResp{
		StatusCode: res.StatusCode,
		Location:   resolveLocation(res, p.Url),
		RespHeader: res.Header,
	}, nil
}

func HttpGet(ctx context.Context, client *http.Client, p *HttpGetParams) (*HttpGetResp, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	reqURL := p.Url
	if len(p.SearchParams) > 0 {
		parsedURL, err := url.Parse(p.Url)
		if err != nil {
			return nil, fmt.Errorf("invalid url: %w", err)
		}
		q := parsedURL.Query()
		for k, v := range p.SearchParams {
			q.Set(k, v)
		}
		parsedURL.RawQuery = q.Encode()
		reqURL = parsedURL.String()
	}

	req, err := http.NewRequestWithContext(ensureContext(ctx), http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	applyRequestMeta(req, p.Header, p.Host, "", false)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := checkStatusError(res.StatusCode, bodyBytes); err != nil {
		return nil, err
	}

	return &HttpGetResp{
		StatusCode: res.StatusCode,
		Location:   resolveLocation(res, reqURL),
		Body:       bodyBytes,
		RespHeader: res.Header,
		Cookies:    extractCookies(client, res, reqURL),
	}, nil
}

func HttpPost(ctx context.Context, client *http.Client, p *HttpPostParams) (*HttpPostResp, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var rawBody []byte
	var contentType string
	var forceContentType bool

	switch p.PostType {
	case "form-urlencoded":
		if p.Body != nil {
			switch bodyVal := p.Body.(type) {
			case map[string]string:
				data := url.Values{}
				for k, v := range bodyVal {
					data.Set(k, v)
				}
				rawBody = []byte(data.Encode())
			case url.Values:
				rawBody = []byte(bodyVal.Encode())
			default:
				return nil, fmt.Errorf("form-urlencoded requires map[string]string or url.Values body, got %T", p.Body)
			}
		}
		contentType = "application/x-www-form-urlencoded"

	case "form-data":
		bodyMap, ok := p.Body.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("form-data requires map[string]interface{} body, got %T", p.Body)
		}
		buf := new(bytes.Buffer)
		writer := multipart.NewWriter(buf)
		for k, v := range bodyMap {
			switch k {
			case "media":
				filePath, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("media field value must be a string path")
				}
				file, err := os.Open(filePath)
				if err != nil {
					return nil, fmt.Errorf("failed to open media file: %w", err)
				}
				part, err := writer.CreateFormFile(k, filepath.Base(file.Name()))
				if err != nil {
					_ = file.Close()
					return nil, fmt.Errorf("failed to create form file: %w", err)
				}
				if _, err := io.Copy(part, file); err != nil {
					_ = file.Close()
					return nil, fmt.Errorf("failed to copy media file: %w", err)
				}
				_ = file.Close()

			case "bufMedia":
				reader, ok := v.(io.Reader)
				if !ok {
					return nil, fmt.Errorf("bufMedia field value must implement io.Reader")
				}
				part, err := writer.CreateFormFile(k, "example.jpg")
				if err != nil {
					return nil, fmt.Errorf("failed to create form file for bufMedia: %w", err)
				}
				if _, err := io.Copy(part, reader); err != nil {
					return nil, fmt.Errorf("failed to copy bufMedia: %w", err)
				}

			default:
				valStr, ok := v.(string)
				if !ok {
					return nil, fmt.Errorf("form-data field '%s' must be string, got %T", k, v)
				}
				if err := writer.WriteField(k, valStr); err != nil {
					return nil, fmt.Errorf("failed to write form field '%s': %w", k, err)
				}
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		rawBody = buf.Bytes()
		contentType = writer.FormDataContentType()
		forceContentType = true // multipart 必须使用带 boundary 的 Content-Type

	default:
		if !isNilPayload(p.Body) {
			body, err := marshalJSONBody(p.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal json body: %w", err)
			}
			if len(body) > 0 {
				rawBody = body
				contentType = "application/json"
			}
		}
	}

	var bodyReader io.Reader
	if len(rawBody) > 0 {
		// 使用 bytes.NewReader 支持 307/308 重定向时自动重置读取流 (GetBody)
		bodyReader = bytes.NewReader(rawBody)
	} else {
		bodyReader = http.NoBody
	}

	req, err := http.NewRequestWithContext(ensureContext(ctx), http.MethodPost, p.Url, bodyReader)
	if err != nil {
		return nil, err
	}
	applyRequestMeta(req, p.Header, p.Host, contentType, forceContentType)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := checkStatusError(res.StatusCode, bodyBytes); err != nil {
		return nil, err
	}

	return &HttpPostResp{
		StatusCode: res.StatusCode,
		Body:       bodyBytes,
		RespHeader: res.Header,
		Cookies:    extractCookies(client, res, p.Url),
	}, nil
}

// HttpPut 语义是完整覆盖。需要在请求里提供资源的全部字段。如果漏掉某些字段，服务器可能会把它们清空或变成默认值。
func HttpPut(ctx context.Context, client *http.Client, p *HttpPutParams) ([]byte, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var bodyReader io.Reader = http.NoBody
	var contentType string

	if !isNilPayload(p.Body) {
		body, err := marshalJSONBody(p.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal json body: %w", err)
		}
		if len(body) > 0 {
			bodyReader = bytes.NewReader(body)
			contentType = "application/json"
		}
	}

	req, err := http.NewRequestWithContext(ensureContext(ctx), http.MethodPut, p.Url, bodyReader)
	if err != nil {
		return nil, err
	}
	applyRequestMeta(req, p.Header, p.Host, contentType, false)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := checkStatusError(res.StatusCode, bodyBytes); err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// HttpPatch 语义是部分修改。只需要在请求里提供发生变化的字段。没有提供的字段会保持原样，不会被删除。
func HttpPatch(ctx context.Context, client *http.Client, p *HttpPatchParams) ([]byte, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var bodyReader io.Reader = http.NoBody
	var contentType string

	if !isNilPayload(p.Body) {
		body, err := marshalJSONBody(p.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal json body: %w", err)
		}
		if len(body) > 0 {
			bodyReader = bytes.NewReader(body)
			contentType = "application/json"
		}
	}

	req, err := http.NewRequestWithContext(ensureContext(ctx), http.MethodPatch, p.Url, bodyReader)
	if err != nil {
		return nil, err
	}
	applyRequestMeta(req, p.Header, p.Host, contentType, false)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := checkStatusError(res.StatusCode, bodyBytes); err != nil {
		return nil, err
	}

	return bodyBytes, nil
}

// HttpDelete 支持携带或不携带 JSON Body 的删除请求。
func HttpDelete(ctx context.Context, client *http.Client, p *HttpDeleteParams) ([]byte, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var bodyReader io.Reader
	var contentType string

	if !isNilPayload(p.Body) {
		body, err := marshalJSONBody(p.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal json body: %w", err)
		}
		if len(body) > 0 {
			bodyReader = bytes.NewReader(body)
			contentType = "application/json"
		}
	}

	req, err := http.NewRequestWithContext(ensureContext(ctx), http.MethodDelete, p.Url, bodyReader)
	if err != nil {
		return nil, err
	}
	applyRequestMeta(req, p.Header, p.Host, contentType, false)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if err := checkStatusError(res.StatusCode, bodyBytes); err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
