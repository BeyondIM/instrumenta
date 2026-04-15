package instrumenta

import (
  "bytes"
  "context"
  "crypto/tls"
  "crypto/x509"
  "encoding/json"
  "fmt"
  "hash/fnv"
  "io"
  "mime/multipart"
  "net"
  "net/http"
  "net/http/cookiejar"
  "net/url"
  "os"
  "path/filepath"
  "strconv"
  "strings"
  "sync"
  "time"

  "github.com/bytedance/sonic"
  "golang.org/x/net/proxy"
  "golang.org/x/net/publicsuffix"
  "golang.org/x/sync/singleflight"
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

type clientBuilder struct {
  timeout               time.Duration
  responseHeaderTimeout time.Duration
  skipInsecure          bool
  caCert                string
  proxyURL              string
  randomProxy           bool
  site                  string
  cookies               string
}
type ClientOption func(*clientBuilder)

// 实现 error 接口
func (e *HTTPError) Error() string {
  if e.Message != "" {
    return e.Message
  }
  return fmt.Sprintf("HTTP request failed with status code %d", e.StatusCode)
}

func transCookies(cookiesStr string) map[string]string {
  cookies := make(map[string]string)
  parts := strings.Split(cookiesStr, "; ")
  for _, part := range parts {
    kv := strings.SplitN(part, "=", 2)
    if len(kv) == 2 {
      cookies[kv[0]] = kv[1]
    }
  }
  return cookies
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
  }
}
func WithRandomProxy(proxyURL string) ClientOption {
  return func(b *clientBuilder) {
    b.proxyURL = proxyURL
    b.randomProxy = true
  }
}

func WithCookies(site string, cookies string) ClientOption {
  return func(b *clientBuilder) {
    b.site = site
    b.cookies = cookies
  }
}

func (b *clientBuilder) transportKey() string {
  h := fnv.New64a()
  fmt.Fprintf(h, "%v_%v_%s_%s_%v",
    b.responseHeaderTimeout,
    b.skipInsecure,
    b.caCert,
    b.proxyURL,
    b.randomProxy,
  )
  return strconv.FormatUint(h.Sum64(), 16)
}

func (b *clientBuilder) getOrBuildTransport() (*http.Transport, error) {
  tKey := b.transportKey()

  // 1. 快速路径（Fast Path）：绝大多数情况都会在这里命中缓存直接返回
  if t, ok := transportCache.Load(tKey); ok {
    return t.(*http.Transport), nil
  }

  // 2. 慢速路径（Slow Path）：使用 singleflight 防止并发创建
  // v 是 fn 返回的值，err 是错误，shared 表示是否被多个调用共享了结果
  v, err, _ := sfGroup.Do(tKey, func() (interface{}, error) {
    // 【重要】Double-Check (双重校验)：
    // 因为在执行到这里之前，可能已经有其他 Goroutine 刚好完成了创建并存入了缓存。
    if t, ok := transportCache.Load(tKey); ok {
      return t, nil
    }

    baseDialer := &net.Dialer{
      Timeout:   10 * time.Second,
      KeepAlive: 30 * time.Second,
    }

    // 随机代理模式：禁用连接复用
    if b.randomProxy {
      baseDialer.KeepAlive = 0
    }

    transport := &http.Transport{
      ResponseHeaderTimeout: b.responseHeaderTimeout,
      TLSHandshakeTimeout:   10 * time.Second,
      IdleConnTimeout:       120 * time.Second,
      MaxIdleConns:          100,
      MaxIdleConnsPerHost:   20,
      MaxConnsPerHost:       50,
    }

    if b.proxyURL != "" {
      proxyURL, err := url.Parse(b.proxyURL)
      if err != nil {
        return nil, fmt.Errorf("invalid proxy URL: %w", err)
      }
      if strings.HasPrefix(b.proxyURL, "socks5") {
        // proxy.Direct 是一个空的默认 Dialer，这意味着程序在连接 SOCKS5 代理服务器本身时，没有使用带有超时的 baseDialer，这可能导致在代理节点网络不通时，请求无限挂起。
        socksDialer, err := proxy.FromURL(proxyURL, baseDialer)
        if err != nil {
          return nil, fmt.Errorf("failed to create socks proxy dialer: %w", err)
        }

        transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
          // 优先尝试断言是否原生支持 Context
          if contextDialer, ok := socksDialer.(proxy.ContextDialer); ok {
            return contextDialer.DialContext(ctx, network, addr)
          }

          // 手动处理 Goroutine 泄漏
          dialCtx, cancel := context.WithTimeout(ctx, baseDialer.Timeout)
          defer cancel()

          type result struct {
            conn net.Conn
            err  error
          }
          resultCh := make(chan result, 1)

          go func() {
            conn, err := socksDialer.Dial(network, addr)
            // 防泄漏核心逻辑：如果外层已经超时退出，立刻关闭迟来的连接
            if dialCtx.Err() != nil && conn != nil {
              conn.Close()
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
      } else if strings.HasPrefix(b.proxyURL, "http") {
        transport.Proxy = http.ProxyURL(proxyURL)
        transport.DialContext = baseDialer.DialContext
      }
    } else {
      transport.DialContext = baseDialer.DialContext
    }

    // 处理 Transport 层面的随机代理配置
    if b.randomProxy {
      transport.DisableKeepAlives = true
      transport.MaxIdleConnsPerHost = 0
      transport.MaxIdleConns = 0
      transport.IdleConnTimeout = 0
    }

    // 配置 TLS
    if b.skipInsecure || len(b.caCert) > 0 {
      tlsConfig := &tls.Config{
        InsecureSkipVerify: b.skipInsecure,
      }
      if len(b.caCert) > 0 {
        caCertPool := x509.NewCertPool()
        if !caCertPool.AppendCertsFromPEM([]byte(b.caCert)) {
          return nil, fmt.Errorf("failed to parse CA certificate") // CA 证书解析失败
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

  // 应用所有选项
  for _, opt := range opts {
    opt(builder)
  }

  // 1. 获取高度复用的共享 Transport（底层 TCP 连接池）
  sharedTransport, err := builder.getOrBuildTransport()
  if err != nil {
    return nil, fmt.Errorf("failed to build transport: %w", err)
  }

  // 2. 每次组装全新的 CookieJar（完全隔离不同调用的会话状态）
  var jar http.CookieJar
  if builder.cookies != "" && builder.site != "" {
    jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
    domainURL, err := url.Parse(builder.site)
    if err != nil {
      return nil, fmt.Errorf("invalid site URL for cookies: %w", err)
    }
    // 动态计算泛域名 (把 quark.cn 变成 .quark.cn)
    // 注意：如果你的 site 本身传的是二级域名比如 pan.quark.cn，
    // 这里加上点就是 .pan.quark.cn (仅对 pan 及其子域生效)。
    // 建议 builder.site 统一传主域！
    cookieDomain := "." + domainURL.Host
    // 如果 Host 自带端口 (quark.cn:8080)，需要先剔除端口
    if strings.Contains(cookieDomain, ":") {
      cookieDomain = strings.Split(cookieDomain, ":")[0]
    }

    cookies := transCookies(builder.cookies)
    var httpCookies []*http.Cookie
    for k, v := range cookies {
      httpCookies = append(httpCookies, &http.Cookie{
        Name:   k,
        Value:  v,
        Domain: cookieDomain, // ✅ 强制指定泛域名属性
        Path:   "/",          // ✅ 最佳实践：作用于全站路径
      })
    }
    jar.SetCookies(domainURL, httpCookies)
  }

  // 3. 返回全新外壳的 Client。轻量级对象，不用担心 GC 压力
  client := &http.Client{
    Transport: sharedTransport,
    Timeout:   builder.timeout,
    Jar:       jar,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
      if len(via) >= 10 { // 限制最大 10 次重定向，防止死循环
        // 返回 ErrUseLastResponse 不会产生 Error，而是让程序成功拿到最后的 3xx 响应
        return http.ErrUseLastResponse
      }
      return nil
    },
  }

  return client, nil
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
    return nil, &HTTPError{
      StatusCode: res.StatusCode,
      Body:       bodyBytes,
      Message:    errMsg,
    }
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
    bodyMap, ok := p.Body.(map[string]string)
    if !ok {
      return nil, fmt.Errorf("form-urlencoded requires map[string]string body, got %T", p.Body)
    }
    data := url.Values{}
    for k, v := range bodyMap {
      data.Set(k, v)
    }
    postBody.WriteString(data.Encode())
    contentType = "application/x-www-form-urlencoded"
  case "form-data":
    writer := multipart.NewWriter(postBody)
    for k, v := range p.Body.(map[string]interface{}) {
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
          file.Close() // 确保出错时关闭文件
          return nil, fmt.Errorf("failed to create form file: %w", err)
        }
        if _, err := io.Copy(part, file); err != nil {
          file.Close()
          return nil, fmt.Errorf("failed to copy media file: %w", err)
        }
        file.Close() // 正常结束时关闭文件
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
        // WriteField 内部自带 CreateFormField 逻辑
        if err := writer.WriteField(k, valStr); err != nil {
          return nil, fmt.Errorf("failed to write form field '%s': %w", k, err)
        }
      }
    }
    contentType = writer.FormDataContentType()
    if err := writer.Close(); err != nil {
      return nil, err
    }
  default:
    body, err := sonic.Marshal(p.Body)
    if err != nil {
      return nil, fmt.Errorf("failed to marshal json body: %w", err)
    }
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
  if client.Jar != nil {
    // resp.Cookies() 拿的是“增量指令”：它只包含服务端在当前这一次请求中，要求客户端新建、修改或删除的 Cookie。
    // jar.Cookies(url) 拿的是“全量状态”：它包含客户端当前针对该域名持有的所有处于有效期内的 Cookie 集合。
    domain, err := url.Parse(p.Url)
    if err == nil { // 这里最好别让 url.Parse 的报错阻断了主流程（走到这里说明请求已经成功了）
      for _, c := range client.Jar.Cookies(domain) {
        cookies[c.Name] = c.Value
      }
    }
  } else {
    for _, c := range res.Cookies() {
      cookies[c.Name] = c.Value
    }
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
    return nil, &HTTPError{
      StatusCode: res.StatusCode,
      Body:       bodyBytes,
      Message:    errMsg,
    }
  }

  return &HttpPostResp{
    Body:       bodyBytes,
    RespHeader: res.Header,
    Cookies:    cookies,
  }, nil
}

func HttpPut(ctx context.Context, client *http.Client, p *HttpPutParams) ([]byte, error) {
  postBody := new(bytes.Buffer)
  body, err := sonic.Marshal(p.Body)
  if err != nil {
    return nil, fmt.Errorf("failed to marshal json body: %w", err)
  }
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
    return nil, &HTTPError{
      StatusCode: res.StatusCode,
      Body:       bodyBytes,
      Message:    errMsg,
    }
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
    return nil, &HTTPError{
      StatusCode: res.StatusCode,
      Body:       bodyBytes,
      Message:    errMsg,
    }
  }

  return bodyBytes, nil
}
