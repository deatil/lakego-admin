package response

import (
    "net/http"

    "github.com/gin-gonic/gin"
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
    ctx *gin.Context
}

// 设置上下文
func (this *Response) WithContext(ctx *gin.Context) *Response {
    this.ctx = ctx

    return this
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

// 将json字符窜以标准json格式返回
// 例如，从redis读取json、格式的字符串，返回给浏览器json格式
func (this *Response) ReturnJsonFromString(jsonStr string) {
    this.ctx.Header("Content-Type", "application/json; charset=utf-8")
    this.ctx.String(this.httpCode, jsonStr)
}

// 返回 json
func (this *Response) ReturnJson(data gin.H) {
    this.ctx.JSON(this.httpCode, data)
}

// 错误暂停
func (this *Response) Abort() {
    this.ctx.Abort()
}

// 响应 json
func (this *Response) ResponseJson(json interface{}) {
    this.ctx.JSON(http.StatusAccepted, &json)
}

// 响应字符
func (this *Response) ResponseString(str string) {
    this.ctx.String(http.StatusAccepted, str)
}

// 错误
func (this *Response) Unauthorized() {
    this.ctx.AbortWithStatus(http.StatusUnauthorized)
}

// 禁止
func (this *Response) Forbidden() {
    this.ctx.AbortWithStatus(http.StatusForbidden)
}

// 下载
func (this *Response) Download(filePath string, fileName string) {
    this.ctx.Header("Content-Type", "application/octet-stream")
    this.ctx.Header("Content-Disposition", "attachment; filename=" + fileName)
    this.ctx.Header("Content-Transfer-Encoding", "binary")
    this.ctx.File(filePath)
}
