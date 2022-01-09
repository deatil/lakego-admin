package response

import (
    "io"
    "strings"
    "net/http"

    "github.com/deatil/lakego-admin/lakego/router"
    viewFetch "github.com/deatil/lakego-admin/lakego/view"
)

// 使用
func New() *Response {
    response := &Response{}

    response.WithHttpCode(http.StatusOK)

    return response
}

/**
 * 响应
 *
 * @create 2021-10-28
 * @author deatil
 */
type Response struct {
    // 请求状态 http.StatusOK
    httpCode int

    // 上下文
    ctx *router.Context
}

// 设置上下文
func (this *Response) WithContext(ctx *router.Context) *Response {
    this.ctx = ctx

    return this
}

// 获取上下文
func (this *Response) GetContext() *router.Context {
    return this.ctx
}

// 设置状态码
func (this *Response) WithHttpCode(httpCode int) *Response {
    this.httpCode = httpCode

    return this
}

// 设置 header
func (this *Response) WithHeader(key string, value string) *Response {
    this.ctx.Header(key, value)

    return this
}

// 批量设置 header
func (this *Response) WithHeaders(headers map[string]string) *Response {
    if len(headers) > 0 {
        for k, v := range headers {
            this.WithHeader(k, v)
        }
    }

    return this
}

// 返回字符
func (this *Response) ReturnString(contents string) {
    this.ctx.String(this.httpCode, contents)
}

// 返回 json
func (this *Response) ReturnJson(data router.H) {
    this.ctx.JSON(this.httpCode, data)
}

// 将json字符窜以标准json格式返回
// 例如，从redis读取json、格式的字符串，返回给浏览器json格式
func (this *Response) ReturnJsonFromString(jsonStr string) {
    this.ctx.Header("Content-Type", "application/json; charset=utf-8")
    this.ctx.String(this.httpCode, jsonStr)
}

// 渲染模板
func (this *Response) Fetch(template string, obj interface{}) {
    hintPathDelimiter := "::"
    if strings.Contains(template, hintPathDelimiter) {
        template = viewFetch.NewViewFinderInstance().Find(template)
    }

    this.ctx.HTML(this.httpCode, template, obj)
}

// 下载
func (this *Response) Download(filePath string, fileName string) {
    this.ctx.Header("Content-Type", "application/octet-stream")
    this.ctx.Header("Content-Disposition", "attachment; filename=" + fileName)
    this.ctx.Header("Content-Transfer-Encoding", "binary")
    this.ctx.File(filePath)
}

/* ===== gin 默认方法 ===== */

// 错误暂停
func (this *Response) Abort() {
    this.ctx.Abort()
}

// 输出状态
func (this *Response) AbortWithStatus(code int) {
    this.ctx.AbortWithStatus(code)
}

// 输出 json 状态
func (this *Response) AbortWithStatusJSON(code int, jsonObj interface{}) {
    this.ctx.AbortWithStatusJSON(code, jsonObj)
}

// 输出错误状态
func (this *Response) AbortWithError(code int, err error) *router.Error {
    return this.ctx.AbortWithError(code, err)
}

// 错误
func (this *Response) Unauthorized() {
    this.AbortWithStatus(http.StatusUnauthorized)
}

// 禁止
func (this *Response) Forbidden() {
    this.AbortWithStatus(http.StatusForbidden)
}

// Status
func (this *Response) Status(code int) {
    this.ctx.Status(code)
}

// SetSameSite
func (this *Response) SetSameSite(samesite http.SameSite) {
    this.ctx.SetSameSite(samesite)
}

// 设置 cookie
func (this *Response) SetCookie(
    name string,
    value string,
    maxAge int,
    path string,
    domain string,
    secure bool,
    httpOnly bool,
) {
    this.ctx.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)
}

// Render
func (this *Response) Render(code int, r router.Render) {
    this.ctx.Render(code, r)
}

// HTML
func (this *Response) HTML(code int, name string, obj interface{}) {
    this.ctx.HTML(code, name, obj)
}

// IndentedJSON
func (this *Response) IndentedJSON(code int, obj interface{}) {
    this.ctx.IndentedJSON(code, obj)
}

// SecureJSON
func (this *Response) SecureJSON(code int, obj interface{}) {
    this.ctx.SecureJSON(code, obj)
}

// JSONP
func (this *Response) JSONP(code int, obj interface{}) {
    this.ctx.JSONP(code, obj)
}

// AsciiJSON
func (this *Response) AsciiJSON(code int, obj interface{}) {
    this.ctx.AsciiJSON(code, obj)
}

// PureJSON
func (this *Response) PureJSON(code int, obj interface{}) {
    this.ctx.PureJSON(code, obj)
}

// XML
func (this *Response) XML(code int, obj interface{}) {
    this.ctx.XML(code, obj)
}

// YAML
func (this *Response) YAML(code int, obj interface{}) {
    this.ctx.YAML(code, obj)
}

// ProtoBuf
func (this *Response) ProtoBuf(code int, obj interface{}) {
    this.ctx.ProtoBuf(code, obj)
}

// Redirect
func (this *Response) Redirect(code int, location string) {
    this.ctx.Redirect(code, location)
}

// Data
func (this *Response) Data(code int, contentType string, data []byte) {
    this.ctx.Data(code, contentType, data)
}

// DataFromReader
func (this *Response) DataFromReader(
    code int,
    contentLength int64,
    contentType string,
    reader io.Reader,
    extraHeaders map[string]string,
) {
    this.ctx.DataFromReader(code, contentLength, contentType, reader, extraHeaders)
}

// File
func (this *Response) File(filepath string) {
    this.ctx.File(filepath)
}

// FileFromFS
func (this *Response) FileFromFS(filepath string, fs http.FileSystem) {
    this.ctx.FileFromFS(filepath, fs)
}

// 下载
func (this *Response) FileAttachment(filepath, filename string) {
    this.ctx.FileAttachment(filepath, filename)
}

// SSEvent
func (this *Response) SSEvent(name string, message interface{}) {
    this.ctx.SSEvent(name, message)
}

// SetAccepted
func (this *Response) SetAccepted(formats ...string) {
    this.ctx.SetAccepted(formats...)
}
