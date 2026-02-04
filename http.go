package instrumenta

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"golang.org/x/net/proxy"
)

type HttpHeadParams struct {
	Header map[string]string
	Url    string
}

type HttpHeadResp struct {
	StatusCode int
}

type HttpGetParams struct {
	Header       map[string]string
	Host         string
	Url          string
	SearchParams map[string]string
}

type HttpGetResp struct {
	Body       []byte
	Location   string
	StatusCode int
	RespHeader http.Header
}

type HttpPostParams struct {
	Body     interface{}
	Header   map[string]string
	PostType string
	Url      string
}

type HttpPostResp struct {
	StatusCode int
	Body       []byte
	RespHeader http.Header
	Cookies    map[string]string
}

type HttpPutParams struct {
	Body   interface{}
	Header map[string]string
	Url    string
}

type HttpDeleteParams struct {
	Body   interface{}
	Header map[string]string
	Url    string
}

type UpstreamErr struct {
	Error string `json:"error"`
}

type clientCache struct {
	clients sync.Map
}

var cache = &clientCache{}

type clientBuilder struct {
	timeout               time.Duration
	responseHeaderTimeout time.Duration
	skipInsecure          bool
	caCert                string
	proxyURL              string
	randomProxy           bool
}
type ClientOption func(*clientBuilder)

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
	}
}
func WithRandomProxy(proxyURL string) ClientOption {
	return func(b *clientBuilder) {
		b.proxyURL = proxyURL
		b.randomProxy = true
	}
}

func (b *clientBuilder) key() string {
	return fmt.Sprintf("%v_%v_%v_%v_%s_%v", b.timeout, b.responseHeaderTimeout, b.skipInsecure, len(b.caCert), b.proxyURL, b.randomProxy)
}

func (b *clientBuilder) build() *http.Client {
	// 1. 先确定基础 Dialer 配置
	baseDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// 如果需要随机代理（禁用连接复用），调整 KeepAlive
	if b.randomProxy {
		baseDialer.KeepAlive = 0
	}

	// 2. 构建 Transport 基础配置
	transport := &http.Transport{
		ResponseHeaderTimeout: b.responseHeaderTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       120 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       50,
	}

	// 3. 根据代理类型设置 DialContext 和 Proxy（只设置一次）
	if b.proxyURL != "" {
		proxyURL, err := url.Parse(b.proxyURL)
		if err != nil {
			return nil
		}

		switch {
		case strings.HasPrefix(b.proxyURL, "socks5"):
			// SOCKS5 代理：使用 proxy 包的 Dialer
			socksDialer, err := proxy.FromURL(proxyURL, proxy.Direct)
			if err != nil {
				return nil
			}

			// 包装 SOCKS5 Dialer，添加超时控制
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				// 创建带超时的 context，参数中的 ctx 指的是 http client timeout deadline
				dialCtx, cancel := context.WithTimeout(ctx, baseDialer.Timeout)
				defer cancel()

				// SOCKS5 Dialer 不支持 DialContext，需要手动处理超时
				type result struct {
					conn net.Conn
					err  error
				}
				resultCh := make(chan result, 1)

				go func() {
					conn, err := socksDialer.Dial(network, addr)
					resultCh <- result{conn, err}
				}()

				select {
				case <-dialCtx.Done():
					return nil, dialCtx.Err()
				case res := <-resultCh:
					return res.conn, res.err
				}
			}

		case strings.HasPrefix(b.proxyURL, "http"):
			// HTTP 代理：使用 Proxy 字段，保持原始 DialContext
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.DialContext = baseDialer.DialContext

		default:
			return nil
		}
	} else {
		// 无代理：直接使用 baseDialer
		transport.DialContext = baseDialer.DialContext
	}

	// 4. 随机代理模式：禁用连接复用
	if b.randomProxy {
		transport.DisableKeepAlives = true
		transport.MaxIdleConnsPerHost = 0
		transport.MaxIdleConns = 0
		transport.IdleConnTimeout = 0
	}

	// 5. 配置 TLS
	if b.skipInsecure || len(b.caCert) > 0 {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: b.skipInsecure,
		}
		if len(b.caCert) > 0 {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM([]byte(b.caCert)) {
				return nil // CA 证书解析失败
			}
			tlsConfig.RootCAs = caCertPool
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Transport: transport,
		Timeout:   b.timeout,
	}
}

func GetClient(opts ...ClientOption) *http.Client {
	builder := &clientBuilder{
		timeout:               60 * time.Second,
		responseHeaderTimeout: 15 * time.Second,
		randomProxy:           false,
	}

	// 应用所有选项
	for _, opt := range opts {
		opt(builder)
	}

	key := builder.key()

	// 尝试从缓存获取
	if client, ok := cache.clients.Load(key); ok {
		return client.(*http.Client)
	}

	// 创建新客户端
	client := builder.build()

	// 缓存客户端
	if existing, loaded := cache.clients.LoadOrStore(key, client); loaded {
		return existing.(*http.Client)
	}

	return client
}

func HttpHead(ctx context.Context, client *http.Client, p *HttpHeadParams) (*HttpHeadResp, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", p.Url, nil)
	if err != nil {
		return &HttpHeadResp{}, err
	}
	for k, v := range p.Header {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return &HttpHeadResp{}, err
	}
	defer res.Body.Close()

	select {
	case <-ctx.Done():
		return &HttpHeadResp{}, ctx.Err()
	default:
	}

	return &HttpHeadResp{
		StatusCode: res.StatusCode,
	}, nil
}

func HttpGet(ctx context.Context, client *http.Client, p *HttpGetParams) (*HttpGetResp, error) {
	reqURL := p.Url
	if len(p.SearchParams) > 0 {
		params := url.Values{}
		for k, v := range p.SearchParams {
			params.Add(k, v)
		}
		reqURL = fmt.Sprintf("%s?%s", p.Url, params.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range p.Header {
		req.Header.Set(k, v)
	}
	if len(p.Host) > 0 {
		req.Host = p.Host
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 { // prevent infinite loops
			return http.ErrUseLastResponse
		}
		return nil
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var upstreamErr UpstreamErr
		_ = json.Unmarshal(bodyBytes, &upstreamErr)

		errMsg := upstreamErr.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("Upstream error (status %d): %s", res.StatusCode, string(bodyBytes))
		}
		return &HttpGetResp{StatusCode: res.StatusCode}, fmt.Errorf(errMsg)
	}

	return &HttpGetResp{
		Location:   res.Request.URL.String(),
		Body:       bodyBytes,
		RespHeader: res.Header,
	}, nil
}

func HttpPost(ctx context.Context, client *http.Client, p *HttpPostParams) (*HttpPostResp, error) {
	postBody := new(bytes.Buffer)
	var contentType string
	switch p.PostType {
	case "form-urlencoded":
		data := url.Values{}
		for k, v := range p.Body.(map[string]string) {
			data.Set(k, v)
		}
		postBody.WriteString(data.Encode())
		contentType = "application/x-www-form-urlencoded"
	case "form-data":
		writer := multipart.NewWriter(postBody)
		for k, v := range p.Body.(map[string]interface{}) {
			switch k {
			case "media":
				file, err := os.Open(v.(string))
				if err != nil {
					return nil, err
				}
				part, err := writer.CreateFormFile(k, filepath.Base(file.Name()))
				if err != nil {
					return nil, err
				}
				io.Copy(part, file)
				file.Close()
			case "bufMedia":
				part, err := writer.CreateFormFile(k, "example.jpg")
				if err != nil {
					return nil, err
				}
				io.Copy(part, v.(io.Reader))
			default:
				_, err := writer.CreateFormField(k)
				if err != nil {
					return nil, err
				}
				writer.WriteField(k, v.(string))
			}
		}
		contentType = writer.FormDataContentType()
		writer.Close()
	default:
		body, _ := sonic.Marshal(p.Body)
		postBody.Write(body)
		contentType = "application/json"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.Url, postBody)
	if err != nil {
		return nil, err
	}
	for k, v := range p.Header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", contentType)

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	cookies := make(map[string]string)
	for _, c := range res.Cookies() {
		cookies[c.Name] = c.Value
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var upstreamErr UpstreamErr
		_ = json.Unmarshal(bodyBytes, &upstreamErr)

		errMsg := upstreamErr.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("Upstream error (status %d): %s", res.StatusCode, string(bodyBytes))
		}
		return &HttpPostResp{StatusCode: res.StatusCode}, fmt.Errorf(errMsg)
	}

	return &HttpPostResp{
		Body:       bodyBytes,
		RespHeader: res.Header,
		Cookies:    cookies,
	}, nil
}

func HttpPut(ctx context.Context, client *http.Client, p *HttpPutParams) ([]byte, error) {
	postBody := new(bytes.Buffer)
	body, _ := sonic.Marshal(p.Body)
	postBody.Write(body)

	req, err := http.NewRequestWithContext(ctx, "PUT", p.Url, postBody)
	if err != nil {
		return nil, err
	}
	for k, v := range p.Header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var upstreamErr UpstreamErr
		_ = json.Unmarshal(bodyBytes, &upstreamErr)

		errMsg := upstreamErr.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("Upstream error (status %d): %s", res.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf(errMsg)
	}

	return bodyBytes, nil
}

func HttpDelete(ctx context.Context, client *http.Client, p *HttpDeleteParams) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", p.Url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range p.Header {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var upstreamErr UpstreamErr
		_ = json.Unmarshal(bodyBytes, &upstreamErr)

		errMsg := upstreamErr.Error
		if errMsg == "" {
			errMsg = fmt.Sprintf("Upstream error (status %d): %s", res.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf(errMsg)
	}

	return bodyBytes, nil
}
