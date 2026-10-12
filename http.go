package instrumenta

import (
  "bytes"
  "container/list"
  "context"
  "crypto/sha256"
  "crypto/tls"
  "crypto/x509"
  "encoding/hex"
  "errors"
  "fmt"
  "io"
  "mime"
  "mime/multipart"
  "net"
  "net/http"
  "net/url"
  "os"
  "path/filepath"
  "sort"
  "strconv"
  "strings"
  "sync"
  "time"
  "unicode/utf8"

  "github.com/bytedance/sonic"
  "golang.org/x/net/proxy"
  "golang.org/x/sync/singleflight"
)

const (
  maxResponseBodyLimit = 64 << 20  // 正常响应体读取上限：64 MB
  maxErrorBodyRetain   = 128 << 10 // 异常响应体最大保留上限：128 KB
  maxErrorDrainBudget  = 512 << 10 // 异常响应体排空预算：最多额外读 512 KB 尝试复用 TCP 长连接
  maxErrorMsgLen       = 512       // 错误消息最终 Rune 上限（包含截断后缀）
  maxTransportCacheCap = 128       // Transport 缓存索引的最大条目数
  maxCACacheCap        = 64        // CA 证书池缓存最大条目数
)

// ErrUploadIncomplete 表示后台上传协程未能确认完全退出（例如调用方传入的 Reader 发生了不可中断的阻塞读取）。
var ErrUploadIncomplete = errors.New("upload stream failed to confirm exit within timeout (goroutine may still be blocked in reader)")

// ErrResponseReceivedUploadIncomplete 表示客户端已接收到 HTTP 响应，但本地上传流未能确认完整生产结束。
type ErrResponseReceivedUploadIncomplete struct {
  Resp       *HttpPostResp
  RequestErr error
  UploadErr  error
}

func (e *ErrResponseReceivedUploadIncomplete) Error() string {
  status := 0
  if e.Resp != nil {
    status = e.Resp.StatusCode
  }
  var sb strings.Builder
  fmt.Fprintf(&sb, "HTTP response received (status %d), but client upload stream was not confirmed complete", status)
  if e.RequestErr != nil {
    fmt.Fprintf(&sb, "; request error: %v", e.RequestErr)
  }
  if e.UploadErr != nil {
    fmt.Fprintf(&sb, "; upload error: %v", e.UploadErr)
  }
  return sb.String()
}

func (e *ErrResponseReceivedUploadIncomplete) Unwrap() []error {
  var errs []error
  if e.RequestErr != nil {
    errs = append(errs, e.RequestErr)
  }
  if e.UploadErr != nil {
    errs = append(errs, e.UploadErr)
  }
  return errs
}

func safeTruncateUTF8(s string, maxRunes int) string {
  if maxRunes <= 0 {
    return ""
  }

  totalRunes := utf8.RuneCountInString(s)
  if totalRunes <= maxRunes {
    return s
  }

  const suffix = "...(truncated)"
  suffixRunes := utf8.RuneCountInString(suffix)

  if maxRunes <= suffixRunes {
    var b strings.Builder
    count := 0
    for _, r := range suffix {
      if count >= maxRunes {
        break
      }
      b.WriteRune(r)
      count++
    }
    return b.String()
  }

  keep := maxRunes - suffixRunes
  var b strings.Builder

  allocSize := 4096
  if maxRunes <= 1024 {
    allocSize = maxRunes * utf8.UTFMax
  }
  b.Grow(allocSize)

  count := 0
  for _, r := range s {
    if count >= keep {
      break
    }
    b.WriteRune(r)
    count++
  }
  b.WriteString(suffix)
  return b.String()
}

// -------------------------------------------------------------
// 有界 CA 证书缓存
// -------------------------------------------------------------

type cachedCAPool struct {
  fingerprint string
  pool        *x509.CertPool
}

type boundedCACache struct {
  mu       sync.Mutex
  capacity int
  items    map[string]*list.Element
  evict    *list.List
}

var globalCACache = &boundedCACache{
  capacity: maxCACacheCap,
  items:    make(map[string]*list.Element),
  evict:    list.New(),
}

func (c *boundedCACache) Get(fp string) (*cachedCAPool, bool) {
  c.mu.Lock()
  defer c.mu.Unlock()
  if elem, ok := c.items[fp]; ok {
    c.evict.MoveToFront(elem)
    return elem.Value.(*cachedCAPool), true
  }
  return nil, false
}

func (c *boundedCACache) Put(entry *cachedCAPool) {
  c.mu.Lock()
  defer c.mu.Unlock()

  if elem, ok := c.items[entry.fingerprint]; ok {
    c.evict.MoveToFront(elem)
    elem.Value = entry
    return
  }
  if c.evict.Len() >= c.capacity {
    oldest := c.evict.Back()
    if oldest != nil {
      c.evict.Remove(oldest)
      kv := oldest.Value.(*cachedCAPool)
      delete(c.items, kv.fingerprint)
    }
  }
  elem := c.evict.PushFront(entry)
  c.items[entry.fingerprint] = elem
}

// -------------------------------------------------------------
// 带锁外闲置连接清理的有界 LRU 缓存
// -------------------------------------------------------------

type lruEntry struct {
  key       string
  transport *http.Transport
}

type boundedTransportCache struct {
  mu       sync.Mutex
  capacity int
  items    map[string]*list.Element
  evict    *list.List
}

var globalTransportCache = &boundedTransportCache{
  capacity: maxTransportCacheCap,
  items:    make(map[string]*list.Element),
  evict:    list.New(),
}

func (c *boundedTransportCache) Get(key string) (*http.Transport, bool) {
  c.mu.Lock()
  defer c.mu.Unlock()

  if elem, ok := c.items[key]; ok {
    c.evict.MoveToFront(elem)
    return elem.Value.(*lruEntry).transport, true
  }
  return nil, false
}

func (c *boundedTransportCache) Put(key string, t *http.Transport) {
  var evictedTransport *http.Transport

  c.mu.Lock()
  if elem, ok := c.items[key]; ok {
    c.evict.MoveToFront(elem)
    entry := elem.Value.(*lruEntry)
    old := entry.transport
    entry.transport = t
    c.mu.Unlock()

    if old != nil && old != t {
      old.CloseIdleConnections()
    }
    return
  }

  if c.evict.Len() >= c.capacity {
    oldest := c.evict.Back()
    if oldest != nil {
      c.evict.Remove(oldest)
      kv := oldest.Value.(*lruEntry)
      delete(c.items, kv.key)
      evictedTransport = kv.transport
    }
  }

  elem := c.evict.PushFront(&lruEntry{key: key, transport: t})
  c.items[key] = elem
  c.mu.Unlock()

  if evictedTransport != nil {
    evictedTransport.CloseIdleConnections()
  }
}

var sfGroup singleflight.Group

// -------------------------------------------------------------
// 错误与数据结构定义
// -------------------------------------------------------------

type HTTPError struct {
  StatusCode    int
  Body          []byte
  Message       string
  RespHeader    http.Header
  BodyTruncated bool
}

func (e *HTTPError) Error() string {
  if e.Message != "" {
    return e.Message
  }
  return fmt.Sprintf("HTTP request failed with status code %d", e.StatusCode)
}

type UpstreamErr struct {
  Error string `json:"error"`
}

type HttpHeadParams struct {
  Header http.Header
  Host   string
  Url    string
}

type HttpHeadResp struct {
  StatusCode int
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
  Header http.Header
  Host   string
  Url    string
}

type clientBuilder struct {
  timeout               time.Duration
  responseHeaderTimeout time.Duration
  skipInsecure          bool
  caCertPEM             string
  caCertFile            string
  proxyURL              string
  rotatingProxy         bool
  sharedJar             http.CookieJar
}

type ClientOption func(*clientBuilder)

// -------------------------------------------------------------
// 中间件：多行/大小写不规范 Cookie 严格有序合并与去重
// -------------------------------------------------------------

type CookieDeduplicateTransport struct {
  Transport http.RoundTripper
}

func (t *CookieDeduplicateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
  if req == nil {
    return nil, errors.New("request cannot be nil")
  }
  if t.Transport == nil {
    return nil, errors.New("underlying transport cannot be nil")
  }

  reqClone := req.Clone(req.Context())
  if req.Header != nil {
    reqClone.Header = req.Header.Clone()
  } else {
    reqClone.Header = make(http.Header)
  }

  var cookieKeysToDelete []string
  for k := range reqClone.Header {
    if strings.EqualFold(k, "Cookie") {
      cookieKeysToDelete = append(cookieKeysToDelete, k)
    }
  }

  sort.Strings(cookieKeysToDelete)

  var cookieHeaders []string
  for _, k := range cookieKeysToDelete {
    cookieHeaders = append(cookieHeaders, reqClone.Header[k]...)
    delete(reqClone.Header, k)
  }

  if len(cookieHeaders) > 0 {
    var keys []string
    seen := make(map[string]string)

    for _, headerVal := range cookieHeaders {
      parts := strings.Split(headerVal, ";")
      for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
          continue
        }
        kv := strings.SplitN(part, "=", 2)
        k := strings.TrimSpace(kv[0])
        v := ""
        if len(kv) == 2 {
          v = kv[1]
        }
        if _, exists := seen[k]; !exists {
          keys = append(keys, k)
        }
        seen[k] = v
      }
    }

    if len(keys) > 0 {
      var cleanCookies []string
      for _, k := range keys {
        cleanCookies = append(cleanCookies, k+"="+seen[k])
      }
      reqClone.Header.Set("Cookie", strings.Join(cleanCookies, "; "))
    }
  }

  return t.Transport.RoundTrip(reqClone)
}

func normalizeContentType(h http.Header, defaultType string) error {
  var keysToDelete []string
  for k := range h {
    if strings.EqualFold(k, "Content-Type") {
      keysToDelete = append(keysToDelete, k)
    }
  }

  if len(keysToDelete) == 0 {
    if defaultType != "" {
      h.Set("Content-Type", defaultType)
    }
    return nil
  }

  sort.Strings(keysToDelete)

  var distinctValues []string
  seenVal := make(map[string]struct{})

  for _, k := range keysToDelete {
    for _, val := range h[k] {
      trimmed := strings.TrimSpace(val)
      if trimmed == "" {
        continue
      }
      if _, exists := seenVal[trimmed]; !exists {
        seenVal[trimmed] = struct{}{}
        distinctValues = append(distinctValues, trimmed)
      }
    }
  }

  if len(distinctValues) > 1 {
    return fmt.Errorf("conflicting Content-Type headers specified: %v", distinctValues)
  }

  for _, k := range keysToDelete {
    delete(h, k)
  }

  if len(distinctValues) == 1 {
    h.Set("Content-Type", distinctValues[0])
  } else if defaultType != "" {
    h.Set("Content-Type", defaultType)
  }

  return nil
}

func reconcileMultipartContentType(h http.Header, actualBoundary string) error {
  var keysToDelete []string
  for k := range h {
    if strings.EqualFold(k, "Content-Type") {
      keysToDelete = append(keysToDelete, k)
    }
  }
  sort.Strings(keysToDelete)

  var distinctValues []string
  seenVal := make(map[string]struct{})
  for _, k := range keysToDelete {
    for _, val := range h[k] {
      trimmed := strings.TrimSpace(val)
      if trimmed != "" {
        if _, exists := seenVal[trimmed]; !exists {
          seenVal[trimmed] = struct{}{}
          distinctValues = append(distinctValues, trimmed)
        }
      }
    }
  }

  if len(distinctValues) > 1 {
    return fmt.Errorf("conflicting Content-Type headers specified for multipart request: %v", distinctValues)
  }

  if len(distinctValues) == 1 {
    val := distinctValues[0]
    mediaType, params, err := mime.ParseMediaType(val)
    if err != nil {
      return fmt.Errorf("invalid multipart Content-Type header '%s': %w", val, err)
    }
    if !strings.EqualFold(mediaType, "multipart/form-data") {
      return fmt.Errorf("mismatched Content-Type '%s' for form-data request (must be multipart/form-data)", val)
    }
    if userBoundary, ok := params["boundary"]; ok && userBoundary != "" {
      if userBoundary != actualBoundary {
        return fmt.Errorf("custom boundary in Content-Type header ('%s') does not match actual multipart body boundary ('%s')", userBoundary, actualBoundary)
      }
    }
  }

  for _, k := range keysToDelete {
    delete(h, k)
  }

  formattedType := mime.FormatMediaType("multipart/form-data", map[string]string{
    "boundary": actualBoundary,
  })
  h.Set("Content-Type", formattedType)
  return nil
}

// -------------------------------------------------------------
// Options 配置函数
// -------------------------------------------------------------

func WithTimeout(timeout time.Duration) ClientOption {
  return func(b *clientBuilder) {
    if timeout < 0 {
      timeout = 0
    }
    b.timeout = timeout
  }
}

func WithResponseHeaderTimeout(responseHeaderTimeout time.Duration) ClientOption {
  return func(b *clientBuilder) {
    if responseHeaderTimeout < 0 {
      responseHeaderTimeout = 0
    }
    b.responseHeaderTimeout = responseHeaderTimeout
  }
}

func WithInsecureSkipVerify() ClientOption {
  return func(b *clientBuilder) {
    b.skipInsecure = true
  }
}

func WithCACert(certOrPath string) ClientOption {
  return func(b *clientBuilder) {
    if strings.Contains(certOrPath, "-----BEGIN CERTIFICATE-----") {
      b.caCertPEM = certOrPath
      b.caCertFile = ""
    } else {
      b.caCertFile = certOrPath
      b.caCertPEM = ""
    }
  }
}

func WithFixedProxy(proxyURL string) ClientOption {
  return func(b *clientBuilder) {
    b.proxyURL = proxyURL
    b.rotatingProxy = false
  }
}

func WithRandomProxy(proxyURL string) ClientOption {
  return func(b *clientBuilder) {
    b.proxyURL = proxyURL
    b.rotatingProxy = true
  }
}

func WithSharedJar(jar http.CookieJar) ClientOption {
  return func(b *clientBuilder) {
    b.sharedJar = jar
  }
}

// -------------------------------------------------------------
// 辅助与规范化
// -------------------------------------------------------------

func appendKeyField(dst *strings.Builder, s string) {
  dst.WriteString(strconv.Itoa(len(s)))
  dst.WriteByte(':')
  dst.WriteString(s)
}

func isValidZoneID(zone string) bool {
  if zone == "" {
    return false
  }
  for i := 0; i < len(zone); i++ {
    c := zone[i]
    if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
      return false
    }
  }
  return true
}

func canonicalizeProxyURL(rawURL string) (string, error) {
  if rawURL == "" {
    return "", nil
  }
  u, err := url.Parse(rawURL)
  if err != nil {
    return "", fmt.Errorf("invalid proxy URL format: %w", err)
  }

  u.Fragment = ""

  scheme := strings.ToLower(u.Scheme)
  if scheme != "http" && scheme != "https" && scheme != "socks5" {
    return "", fmt.Errorf("unsupported proxy scheme '%s': only http, https and socks5 are supported", u.Scheme)
  }
  u.Scheme = scheme

  host := u.Hostname()
  if host == "" {
    return "", errors.New("proxy URL must contain a non-empty host")
  }

  portStr := u.Port()
  var pNum int
  if portStr != "" {
    pNum, err = strconv.Atoi(portStr)
    if err != nil || pNum <= 0 || pNum > 65535 {
      return "", fmt.Errorf("invalid proxy port: %s", portStr)
    }
  }

  isDefaultPort := (scheme == "http" && pNum == 80) || (scheme == "https" && pNum == 443)
  if isDefaultPort {
    pNum = 0
  }

  formattedPort := ""
  if pNum > 0 {
    formattedPort = strconv.Itoa(pNum)
  }

  if idx := strings.Index(host, "%"); idx != -1 {
    ipPart := host[:idx]
    zonePart := host[idx+1:]
    if net.ParseIP(ipPart) == nil {
      return "", fmt.Errorf("invalid IPv6 ip segment in zone: %s", ipPart)
    }
    if !isValidZoneID(zonePart) {
      return "", fmt.Errorf("invalid IPv6 zone identifier: %s", zonePart)
    }
    encodedHost := "[" + ipPart + "%25" + zonePart + "]"
    if formattedPort != "" {
      u.Host = encodedHost + ":" + formattedPort
    } else {
      u.Host = encodedHost
    }
  } else if net.ParseIP(host) != nil {
    if strings.Contains(host, ":") {
      if formattedPort != "" {
        u.Host = "[" + host + "]:" + formattedPort
      } else {
        u.Host = "[" + host + "]"
      }
    } else {
      if formattedPort != "" {
        u.Host = host + ":" + formattedPort
      } else {
        u.Host = host
      }
    }
  } else {
    host = strings.ToLower(host)
    if formattedPort != "" {
      u.Host = net.JoinHostPort(host, formattedPort)
    } else {
      u.Host = host
    }
  }

  return u.String(), nil
}

func resolveCACertPool(pemData, filePath string) (*x509.CertPool, string, error) {
  if pemData == "" && filePath == "" {
    return nil, "", nil
  }

  var rawBytes []byte
  if filePath != "" {
    data, err := os.ReadFile(filePath)
    if err != nil {
      return nil, "", fmt.Errorf("read CA certificate file '%s': %w", filePath, err)
    }
    rawBytes = data
  } else {
    rawBytes = []byte(pemData)
  }

  h := sha256.Sum256(rawBytes)
  fp := hex.EncodeToString(h[:])

  if cached, ok := globalCACache.Get(fp); ok {
    return cached.pool, cached.fingerprint, nil
  }

  pool, err := x509.SystemCertPool()
  if err != nil {
    return nil, "", fmt.Errorf("load system root CA pool: %w", err)
  }
  if pool == nil {
    return nil, "", errors.New("load system root CA pool: returned nil pool")
  }
  if !pool.AppendCertsFromPEM(rawBytes) {
    return nil, "", errors.New("failed to parse CA certificate from PEM data")
  }

  globalCACache.Put(&cachedCAPool{
    fingerprint: fp,
    pool:        pool,
  })
  return pool, fp, nil
}

func (b *clientBuilder) buildTransportKey(caFingerprint, canonProxy string) string {
  var sb strings.Builder
  appendKeyField(&sb, strconv.FormatInt(b.responseHeaderTimeout.Nanoseconds(), 10))
  appendKeyField(&sb, strconv.FormatBool(b.skipInsecure))
  appendKeyField(&sb, caFingerprint)
  appendKeyField(&sb, canonProxy)
  appendKeyField(&sb, strconv.FormatBool(b.rotatingProxy))
  return sb.String()
}

func (b *clientBuilder) getOrBuildTransport() (*http.Transport, error) {
  canonProxy, err := canonicalizeProxyURL(b.proxyURL)
  if err != nil {
    return nil, fmt.Errorf("canonicalize proxy URL: %w", err)
  }

  caPool, caFingerprint, err := resolveCACertPool(b.caCertPEM, b.caCertFile)
  if err != nil {
    return nil, fmt.Errorf("resolve CA certificates: %w", err)
  }

  tKey := b.buildTransportKey(caFingerprint, canonProxy)

  if t, ok := globalTransportCache.Get(tKey); ok {
    return t, nil
  }

  v, err, _ := sfGroup.Do(tKey, func() (interface{}, error) {
    if t, ok := globalTransportCache.Get(tKey); ok {
      return t, nil
    }

    baseDialer := &net.Dialer{
      Timeout:   10 * time.Second,
      KeepAlive: 30 * time.Second,
    }

    transport := &http.Transport{
      ForceAttemptHTTP2:     !b.rotatingProxy,
      ResponseHeaderTimeout: b.responseHeaderTimeout,
      TLSHandshakeTimeout:   10 * time.Second,
      IdleConnTimeout:       90 * time.Second,
      MaxIdleConns:          100,
      MaxIdleConnsPerHost:   20,
      MaxConnsPerHost:       100,
    }

    if b.rotatingProxy {
      baseDialer.KeepAlive = -1
      transport.DisableKeepAlives = true
    }

    if canonProxy != "" {
      parsedProxy, err := url.Parse(canonProxy)
      if err != nil {
        return nil, fmt.Errorf("parse canonical proxy URL: %w", err)
      }

      switch parsedProxy.Scheme {
      case "socks5":
        socksDialer, err := proxy.FromURL(parsedProxy, baseDialer)
        if err != nil {
          return nil, fmt.Errorf("create socks5 dialer: %w", err)
        }

        transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
          if contextDialer, ok := socksDialer.(proxy.ContextDialer); ok {
            return contextDialer.DialContext(ctx, network, addr)
          }

          type dialResult struct {
            conn net.Conn
            err  error
          }
          ch := make(chan dialResult)

          go func() {
            c, dErr := socksDialer.Dial(network, addr)

            if ctx.Err() != nil {
              if c != nil {
                _ = c.Close()
              }
              return
            }

            select {
            case ch <- dialResult{conn: c, err: dErr}:
            case <-ctx.Done():
              if c != nil {
                _ = c.Close()
              }
            }
          }()

          select {
          case <-ctx.Done():
            return nil, ctx.Err()
          case res := <-ch:
            return res.conn, res.err
          }
        }

      case "http", "https":
        transport.Proxy = http.ProxyURL(parsedProxy)
        transport.DialContext = baseDialer.DialContext
      }
    } else {
      transport.DialContext = baseDialer.DialContext
    }

    if b.skipInsecure || caPool != nil {
      tlsConfig := &tls.Config{
        InsecureSkipVerify: b.skipInsecure,
      }
      if caPool != nil {
        tlsConfig.RootCAs = caPool
      }
      transport.TLSClientConfig = tlsConfig
    }

    globalTransportCache.Put(tKey, transport)
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
    rotatingProxy:         false,
  }

  for _, opt := range opts {
    if opt == nil {
      return nil, errors.New("client option cannot be nil")
    }
    opt(builder)
  }

  sharedTransport, err := builder.getOrBuildTransport()
  if err != nil {
    return nil, fmt.Errorf("build transport: %w", err)
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

// -------------------------------------------------------------
// 核心请求执行引擎
// -------------------------------------------------------------

func doExecute(client *http.Client, req *http.Request) ([]byte, *http.Response, error) {
  res, err := client.Do(req)
  if err != nil {
    return nil, nil, err
  }
  defer res.Body.Close()

  if res.StatusCode < 200 || res.StatusCode >= 300 {
    limitedReader := io.LimitReader(res.Body, maxErrorBodyRetain+1)
    errRawBytes, rErr := io.ReadAll(limitedReader)
    if rErr != nil {
      return nil, res, fmt.Errorf("read error response body (status %d): %w", res.StatusCode, rErr)
    }

    isTruncated := false
    n := len(errRawBytes)
    if n > maxErrorBodyRetain {
      n = maxErrorBodyRetain
      isTruncated = true
    }
    errBody := append([]byte(nil), errRawBytes[:n]...)

    _, _ = io.CopyN(io.Discard, res.Body, maxErrorDrainBudget)

    var upstreamErr UpstreamErr
    _ = sonic.Unmarshal(errBody, &upstreamErr)

    errMsg := upstreamErr.Error
    if errMsg == "" {
      snippetLen := len(errBody)
      if snippetLen > 256 {
        snippetLen = 256
      }
      errMsg = fmt.Sprintf("Upstream error (status %d): %s", res.StatusCode, string(errBody[:snippetLen]))
    }
    errMsg = safeTruncateUTF8(errMsg, maxErrorMsgLen)

    return nil, res, &HTTPError{
      StatusCode:    res.StatusCode,
      Body:          errBody,
      Message:       errMsg,
      RespHeader:    res.Header.Clone(),
      BodyTruncated: isTruncated,
    }
  }

  bodyBytes, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBodyLimit+1))
  if err != nil {
    return nil, nil, fmt.Errorf("read response body: %w", err)
  }
  if len(bodyBytes) > maxResponseBodyLimit {
    return nil, nil, fmt.Errorf("response body exceeds limit of %d bytes", maxResponseBodyLimit)
  }

  return bodyBytes, res, nil
}

// -------------------------------------------------------------
// 外部调用方法
// -------------------------------------------------------------

func HttpHead(ctx context.Context, client *http.Client, p *HttpHeadParams) (*HttpHeadResp, error) {
  if client == nil {
    return nil, errors.New("client cannot be nil")
  }
  if p == nil {
    return nil, errors.New("params cannot be nil")
  }
  if ctx == nil {
    ctx = context.Background()
  }

  req, err := http.NewRequestWithContext(ctx, "HEAD", p.Url, nil)
  if err != nil {
    return nil, err
  }
  if p.Header != nil {
    req.Header = p.Header.Clone()
  }
  if len(p.Host) > 0 {
    req.Host = p.Host
  }

  res, err := client.Do(req)
  if err != nil {
    return nil, err
  }
  defer res.Body.Close()

  if res.StatusCode < 200 || res.StatusCode >= 300 {
    _, _ = io.CopyN(io.Discard, res.Body, maxErrorDrainBudget)

    return nil, &HTTPError{
      StatusCode: res.StatusCode,
      Message:    fmt.Sprintf("HEAD request failed with status code %d", res.StatusCode),
      RespHeader: res.Header.Clone(),
    }
  }

  return &HttpHeadResp{
    StatusCode: res.StatusCode,
    RespHeader: res.Header,
  }, nil
}

func HttpGet(ctx context.Context, client *http.Client, p *HttpGetParams) (*HttpGetResp, error) {
  if client == nil {
    return nil, errors.New("client cannot be nil")
  }
  if p == nil {
    return nil, errors.New("params cannot be nil")
  }
  if ctx == nil {
    ctx = context.Background()
  }

  reqURL := p.Url
  if len(p.SearchParams) > 0 {
    u, err := url.Parse(p.Url)
    if err != nil {
      return nil, fmt.Errorf("parse request URL: %w", err)
    }
    query := u.Query()
    for k, v := range p.SearchParams {
      query.Set(k, v)
    }
    u.RawQuery = query.Encode()
    reqURL = u.String()
  }

  req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
  if err != nil {
    return nil, err
  }
  if p.Header != nil {
    req.Header = p.Header.Clone()
  }
  if len(p.Host) > 0 {
    req.Host = p.Host
  }

  bodyBytes, res, err := doExecute(client, req)
  if err != nil {
    return nil, err
  }

  return &HttpGetResp{
    Location:   res.Request.URL.String(),
    StatusCode: res.StatusCode,
    Body:       bodyBytes,
    RespHeader: res.Header,
    Cookies:    res.Cookies(),
  }, nil
}

type uploadStatus struct {
  err              error
  producerFinished bool
}

type formField struct {
  key string
  val interface{}
}

func HttpPost(ctx context.Context, client *http.Client, p *HttpPostParams) (*HttpPostResp, error) {
  if client == nil {
    return nil, errors.New("client cannot be nil")
  }
  if p == nil {
    return nil, errors.New("params cannot be nil")
  }
  if ctx == nil {
    ctx = context.Background()
  }

  headerClone := make(http.Header)
  if p.Header != nil {
    headerClone = p.Header.Clone()
  }

  var reqBody io.Reader
  var pr *io.PipeReader
  var pw *io.PipeWriter
  var isStreaming bool
  var streamingWriter *multipart.Writer
  var uploadStatusChan chan uploadStatus
  var frozenFields []formField

  uploadCtx, cancelUpload := context.WithCancel(ctx)
  defer cancelUpload()

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
    reqBody = strings.NewReader(data.Encode())
    if err := normalizeContentType(headerClone, "application/x-www-form-urlencoded"); err != nil {
      return nil, err
    }

  case "form-data":
    bodyMap, ok := p.Body.(map[string]interface{})
    if !ok {
      return nil, fmt.Errorf("form-data requires map[string]interface{} body, got %T", p.Body)
    }

    keys := make([]string, 0, len(bodyMap))
    for k := range bodyMap {
      keys = append(keys, k)
    }
    sort.Strings(keys)
    frozenFields = make([]formField, 0, len(keys))
    for _, k := range keys {
      frozenFields = append(frozenFields, formField{key: k, val: bodyMap[k]})
    }

    pr, pw = io.Pipe()
    reqBody = pr
    isStreaming = true
    uploadStatusChan = make(chan uploadStatus, 1)

    streamingWriter = multipart.NewWriter(pw)

    if err := reconcileMultipartContentType(headerClone, streamingWriter.Boundary()); err != nil {
      _ = pr.CloseWithError(err)
      _ = pw.CloseWithError(err)
      return nil, err
    }

  default:
    body, err := sonic.Marshal(p.Body)
    if err != nil {
      return nil, fmt.Errorf("marshal json body: %w", err)
    }
    reqBody = bytes.NewReader(body)
    if err := normalizeContentType(headerClone, "application/json"); err != nil {
      return nil, err
    }
  }

  req, err := http.NewRequestWithContext(ctx, "POST", p.Url, reqBody)
  if err != nil {
    if isStreaming {
      _ = pr.CloseWithError(err)
      _ = pw.CloseWithError(err)
    }
    return nil, err
  }

  req.Header = headerClone
  if len(p.Host) > 0 {
    req.Host = p.Host
  }

  if isStreaming {
    writer := streamingWriter

    go func() {
      var writeErr error
      var fullyFinished bool

      defer func() {
        if writeErr != nil {
          _ = pw.CloseWithError(writeErr)
        } else {
          _ = pw.Close()
        }
        uploadStatusChan <- uploadStatus{
          err:              writeErr,
          producerFinished: fullyFinished,
        }
      }()

      for _, f := range frozenFields {
        k := f.key
        v := f.val

        select {
        case <-uploadCtx.Done():
          writeErr = uploadCtx.Err()
          return
        default:
        }

        switch k {
        case "media":
          filePath, ok := v.(string)
          if !ok {
            writeErr = fmt.Errorf("media field value must be a string path")
            return
          }
          file, err := os.Open(filePath)
          if err != nil {
            writeErr = fmt.Errorf("open media file: %w", err)
            return
          }
          part, err := writer.CreateFormFile(k, filepath.Base(file.Name()))
          if err != nil {
            _ = file.Close()
            writeErr = fmt.Errorf("create form file: %w", err)
            return
          }
          _, copyErr := io.Copy(part, file)
          _ = file.Close()
          if copyErr != nil {
            writeErr = fmt.Errorf("stream media file: %w", copyErr)
            return
          }

        case "bufMedia":
          reader, ok := v.(io.Reader)
          if !ok {
            writeErr = fmt.Errorf("bufMedia field value must implement io.Reader")
            return
          }
          part, err := writer.CreateFormFile(k, "buffer.bin")
          if err != nil {
            writeErr = fmt.Errorf("create form file for bufMedia: %w", err)
            return
          }

          if _, err := io.Copy(part, reader); err != nil {
            writeErr = fmt.Errorf("stream bufMedia: %w", err)
            return
          }

        default:
          valStr := fmt.Sprintf("%v", v)
          if err := writer.WriteField(k, valStr); err != nil {
            writeErr = fmt.Errorf("write form field '%s': %w", k, err)
            return
          }
        }
      }

      if err := writer.Close(); err != nil {
        writeErr = err
      } else {
        fullyFinished = true
      }
    }()
  }

  execClient := client
  if isStreaming {
    streamClient := *client
    streamClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
      if len(via) > 0 {
        return http.ErrUseLastResponse
      }
      return nil
    }
    execClient = &streamClient
  }

  bodyBytes, res, reqErr := doExecute(execClient, req)

  cancelUpload()

  if isStreaming {
    if reqErr != nil {
      _ = pr.CloseWithError(reqErr)
    } else {
      _ = pr.Close()
    }

    select {
    case status := <-uploadStatusChan:
      if !status.producerFinished {
        var partialResp *HttpPostResp
        if res != nil {
          partialResp = &HttpPostResp{
            StatusCode: res.StatusCode,
            Body:       bodyBytes,
            RespHeader: res.Header,
            Cookies:    res.Cookies(),
          }
        }

        uploadErr := status.err
        if uploadErr == nil {
          uploadErr = errors.New("upload stream was cut off before all fields and boundary were written")
        } else {
          uploadErr = fmt.Errorf("upload stream was cut off before completion: %w", uploadErr)
        }

        if partialResp != nil {
          return nil, &ErrResponseReceivedUploadIncomplete{
            Resp:       partialResp,
            RequestErr: reqErr,
            UploadErr:  uploadErr,
          }
        }

        if reqErr != nil {
          return nil, errors.Join(
            fmt.Errorf("HTTP request failed: %w", reqErr),
            uploadErr,
          )
        }
        return nil, uploadErr
      }

      if reqErr != nil {
        return nil, reqErr
      }

    case <-time.After(2 * time.Second):
      if reqErr != nil {
        return nil, errors.Join(
          fmt.Errorf("HTTP request failed: %w", reqErr),
          ErrUploadIncomplete,
        )
      }
      return nil, ErrUploadIncomplete
    }
  }

  if reqErr != nil {
    return nil, reqErr
  }

  return &HttpPostResp{
    StatusCode: res.StatusCode,
    Body:       bodyBytes,
    RespHeader: res.Header,
    Cookies:    res.Cookies(),
  }, nil
}

func HttpPut(ctx context.Context, client *http.Client, p *HttpPutParams) ([]byte, error) {
  if client == nil {
    return nil, errors.New("client cannot be nil")
  }
  if p == nil {
    return nil, errors.New("params cannot be nil")
  }
  if ctx == nil {
    ctx = context.Background()
  }

  body, err := sonic.Marshal(p.Body)
  if err != nil {
    return nil, fmt.Errorf("marshal json body: %w", err)
  }

  req, err := http.NewRequestWithContext(ctx, "PUT", p.Url, bytes.NewReader(body))
  if err != nil {
    return nil, err
  }
  if p.Header != nil {
    req.Header = p.Header.Clone()
  } else {
    req.Header = make(http.Header)
  }
  if err := normalizeContentType(req.Header, "application/json"); err != nil {
    return nil, err
  }

  if len(p.Host) > 0 {
    req.Host = p.Host
  }

  bodyBytes, _, err := doExecute(client, req)
  return bodyBytes, err
}

func HttpPatch(ctx context.Context, client *http.Client, p *HttpPatchParams) ([]byte, error) {
  if client == nil {
    return nil, errors.New("client cannot be nil")
  }
  if p == nil {
    return nil, errors.New("params cannot be nil")
  }
  if ctx == nil {
    ctx = context.Background()
  }

  body, err := sonic.Marshal(p.Body)
  if err != nil {
    return nil, fmt.Errorf("marshal json body: %w", err)
  }

  req, err := http.NewRequestWithContext(ctx, "PATCH", p.Url, bytes.NewReader(body))
  if err != nil {
    return nil, err
  }
  if p.Header != nil {
    req.Header = p.Header.Clone()
  } else {
    req.Header = make(http.Header)
  }
  if err := normalizeContentType(req.Header, "application/json"); err != nil {
    return nil, err
  }

  if len(p.Host) > 0 {
    req.Host = p.Host
  }

  bodyBytes, _, err := doExecute(client, req)
  return bodyBytes, err
}

func HttpDelete(ctx context.Context, client *http.Client, p *HttpDeleteParams) ([]byte, error) {
  if client == nil {
    return nil, errors.New("client cannot be nil")
  }
  if p == nil {
    return nil, errors.New("params cannot be nil")
  }
  if ctx == nil {
    ctx = context.Background()
  }

  req, err := http.NewRequestWithContext(ctx, "DELETE", p.Url, nil)
  if err != nil {
    return nil, err
  }
  if p.Header != nil {
    req.Header = p.Header.Clone()
  }
  if len(p.Host) > 0 {
    req.Host = p.Host
  }

  bodyBytes, _, err := doExecute(client, req)
  return bodyBytes, err
}
