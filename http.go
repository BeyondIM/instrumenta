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

const (
	maxErrorMsgBodyLen = 512 // 错误信息中内嵌响应体的最大长度，防止巨型 HTML 报错页撑爆日志
	maxRetryAttempts   = 3   // 代理网络层瞬断最大尝试次数
)

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
	Transport      http.RoundTripper
	DefaultTimeout time.Duration
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

// classifyCookie 判断 Cookie Key 的类型并生成独立的归类组标识
func classifyCookie(k string) (bool, string) {
	if isDynamicHexLen(len(k)) && isHexBytes(k) {
		return true, "__PURE_HEX_" + strconv.Itoa(len(k)) + "__"
	}
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

	var evictedKeys []string

	cookieHeaders := req.Header.Values("Cookie")
	if len(cookieHeaders) > 0 {
		seen := make(map[string]int)
		dynamicGroupIdx := make(map[string]int)
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

					if isDyn, groupKey := classifyCookie(k); isDyn {
						needRewrite = true
						if gIdx, exists := dynamicGroupIdx[groupKey]; exists {
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

	if t, ok := transportCache.Load(tKey); ok {
		return t.(*http.Transport), nil
	}

	v, err, _ := sfGroup.Do(tKey, func() (interface{}, error) {
		if t, ok := transportCache.Load(tKey); ok {
			return t, nil
		}

		baseDialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		// 动态匹配 TLS 握手超时（全局对所有 HTTP Method 生效），防止代理池首包重试时客户端提前超时
		tlsTimeout := 10 * time.Second
		if b.responseHeaderTimeout > tlsTimeout {
			tlsTimeout = b.responseHeaderTimeout
		}

		transport := &http.Transport{
			ForceAttemptHTTP2:     true,
			ResponseHeaderTimeout: b.responseHeaderTimeout,
			TLSHandshakeTimeout:   tlsTimeout,
			IdleConnTimeout:       120 * time.Second,
			MaxIdleConns:          500,
			MaxIdleConnsPerHost:   100,
			MaxConnsPerHost:       200,
		}

		if b.randomProxy {
			baseDialer.KeepAlive = -1
			transport.DisableKeepAlives = true
			transport.MaxIdleConnsPerHost = -1
			transport.MaxIdleConns = 0
			transport.IdleConnTimeout = 0
			transport.ForceAttemptHTTP2 = false
			transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
		}

		if b.proxyURL != "" {
			proxyURL, err := url.Parse(b.proxyURL)
			if err != nil || proxyURL.Host == "" {
				return nil, fmt.Errorf("invalid proxy URL %q: missing host or malformed", b.proxyURL)
			}

			scheme := strings.ToLower(proxyURL.Scheme)
			switch scheme {
			case "socks5", "socks5h":
				normalizedURL := *proxyURL
				normalizedURL.Scheme = "socks5"

				socksDialer, err := proxy.FromURL(&normalizedURL, baseDialer)
				if err != nil {
					return nil, fmt.Errorf("failed to create socks proxy dialer: %w", err)
				}
				contextDialer, ok := socksDialer.(proxy.ContextDialer)
				if !ok {
					return nil, fmt.Errorf("socks proxy dialer does not support ContextDialer")
				}
				transport.DialContext = contextDialer.DialContext
			case "http", "https":
				transport.Proxy = http.ProxyURL(proxyURL)
				transport.DialContext = baseDialer.DialContext
			default:
				return nil, fmt.Errorf("unsupported proxy scheme in URL: %s", b.proxyURL)
			}
		} else {
			transport.DialContext = baseDialer.DialContext
		}

		if b.skipInsecure || b.caCert != "" || b.randomProxy {
			nextProtos := []string{"h2", "http/1.1"}
			if b.randomProxy {
				nextProtos = []string{"http/1.1"}
			}
			tlsConfig := &tls.Config{
				InsecureSkipVerify: b.skipInsecure,
				MinVersion:         tls.VersionTLS12,
				NextProtos:         nextProtos,
			}
			if b.caCert != "" {
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
		Transport: &CookieDeduplicateTransport{
			Transport:      sharedTransport,
			DefaultTimeout: builder.timeout,
		},
		Timeout: 0,
		Jar:     builder.sharedJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return client, nil
}

func WithJar(client *http.Client, jar http.CookieJar) *http.Client {
	if client == nil {
		return nil
	}
	cloned := *client
	cloned.Jar = jar
	return &cloned
}

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

func ensureContextWithTimeout(ctx context.Context, client *http.Client) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && client != nil {
		var timeout time.Duration
		if client.Timeout > 0 {
			timeout = client.Timeout
		} else if cdt, ok := client.Transport.(*CookieDeduplicateTransport); ok && cdt.DefaultTimeout > 0 {
			timeout = cdt.DefaultTimeout
		}
		if timeout > 0 {
			return context.WithTimeout(ctx, timeout)
		}
	}
	return ctx, func() {}
}

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
		req.Host = hdrHost
		req.Header.Del("Host")
	}
}

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

	seen := make(map[string]int)
	dynamicGroupIdx := make(map[string]int)
	result := make([]*http.Cookie, 0, len(rawCookies))

	for _, c := range rawCookies {
		if c == nil || c.Name == "" {
			continue
		}
		if isDyn, groupKey := classifyCookie(c.Name); isDyn {
			if gIdx, exists := dynamicGroupIdx[groupKey]; exists {
				result[gIdx] = c
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

// isRetriableNetErr 判断是否为代理池瞬断、数据损坏或 MAC 校验失败的可重试底层网络错误
func isRetriableNetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "EOF") ||
		strings.Contains(s, "reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "TLS handshake timeout") ||
		strings.Contains(s, "bad record MAC") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "connection refused")
}

// doWithRetry 通用底层请求执行器：支持所有 HTTP Method (GET/HEAD/POST/PUT/PATCH/DELETE)
// 在遇到代理节点 EOF、bad record MAC、连接重置时自动重置 Body Reader 并切换下一个代理节点重试
func doWithRetry(
	ctx context.Context,
	client *http.Client,
	method string,
	reqURL string,
	header http.Header,
	host string,
	rawBody []byte,
	contentType string,
	forceContentType bool,
	discardBody bool,
) (*http.Response, []byte, error) {
	reqCtx, cancel := ensureContextWithTimeout(ctx, client)
	defer cancel()

	var lastErr error

	for attempt := 1; attempt <= maxRetryAttempts; attempt++ {
		if reqCtx.Err() != nil {
			return nil, nil, reqCtx.Err()
		}

		// 每次重试都基于 rawBody 创建全新的 Reader，防止 POST/PUT/PATCH 重试时发送空 Body
		var bodyReader io.Reader
		if len(rawBody) > 0 {
			bodyReader = bytes.NewReader(rawBody)
		} else {
			bodyReader = http.NoBody
		}

		req, err := http.NewRequestWithContext(reqCtx, method, reqURL, bodyReader)
		if err != nil {
			return nil, nil, err
		}
		applyRequestMeta(req, header, host, contentType, forceContentType)

		res, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < maxRetryAttempts && isRetriableNetErr(err) {
				continue
			}
			return nil, nil, err
		}

		if discardBody {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if err := checkStatusError(res.StatusCode, nil); err != nil {
				return nil, nil, err
			}
			return res, nil, nil
		}

		bodyBytes, readErr := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if attempt < maxRetryAttempts && isRetriableNetErr(readErr) {
				continue
			}
			return nil, nil, readErr
		}

		if err := checkStatusError(res.StatusCode, bodyBytes); err != nil {
			return nil, nil, err // 业务状态码错误 (如 404/400/500) 直接返回，不进行网络重试
		}

		return res, bodyBytes, nil
	}

	return nil, nil, lastErr
}

func HttpHead(ctx context.Context, client *http.Client, p *HttpHeadParams) (*HttpHeadResp, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	res, _, err := doWithRetry(ctx, client, http.MethodHead, p.Url, p.Header, p.Host, nil, "", false, true)
	if err != nil {
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

	res, bodyBytes, err := doWithRetry(ctx, client, http.MethodGet, reqURL, p.Header, p.Host, nil, "", false, false)
	if err != nil {
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
		forceContentType = true

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

	res, bodyBytes, err := doWithRetry(ctx, client, http.MethodPost, p.Url, p.Header, p.Host, rawBody, contentType, forceContentType, false)
	if err != nil {
		return nil, err
	}

	return &HttpPostResp{
		StatusCode: res.StatusCode,
		Body:       bodyBytes,
		RespHeader: res.Header,
		Cookies:    extractCookies(client, res, p.Url),
	}, nil
}

// HttpPut 语义是完整覆盖。
func HttpPut(ctx context.Context, client *http.Client, p *HttpPutParams) ([]byte, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var rawBody []byte
	var contentType string

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

	_, bodyBytes, err := doWithRetry(ctx, client, http.MethodPut, p.Url, p.Header, p.Host, rawBody, contentType, false, false)
	return bodyBytes, err
}

// HttpPatch 语义是部分修改。
func HttpPatch(ctx context.Context, client *http.Client, p *HttpPatchParams) ([]byte, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var rawBody []byte
	var contentType string

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

	_, bodyBytes, err := doWithRetry(ctx, client, http.MethodPatch, p.Url, p.Header, p.Host, rawBody, contentType, false, false)
	return bodyBytes, err
}

// HttpDelete 支持携带或不携带 JSON Body 的删除请求。
func HttpDelete(ctx context.Context, client *http.Client, p *HttpDeleteParams) ([]byte, error) {
	if client == nil || p == nil {
		return nil, errors.New("client and params must not be nil")
	}

	var rawBody []byte
	var contentType string

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

	_, bodyBytes, err := doWithRetry(ctx, client, http.MethodDelete, p.Url, p.Header, p.Host, rawBody, contentType, false, false)
	return bodyBytes, err
}
