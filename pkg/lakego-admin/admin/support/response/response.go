package response

import (
    gin "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/http/request"
    "github.com/deatil/lakego-admin/lakego/http/response"

    "github.com/deatil/lakego-admin/admin/support/http/code"
)

// 使用
func New() *Response {
    resp := &Response{}

    return resp
}

// 设置 header
func SetHeader(ctx *gin.Context, key string, value string) {
    New().SetHeader(ctx, key, value)
}

// 返回字符
func ReturnString(ctx *gin.Context, data string, httpCode ...int) {
    New().ReturnString(ctx, data, httpCode...)
}

// 将json字符窜以标准json格式返回
func ReturnJsonFromString(ctx *gin.Context, jsonStr string, httpCode ...int) {
    New().ReturnJsonFromString(ctx, jsonStr, httpCode...)
}

// 返回 json
func ReturnJson(
    ctx *gin.Context,
    success bool,
    dataCode int,
    msg string,
    data interface{},
    httpCode ...int,
) {
    New().ReturnJson(ctx, success, dataCode, msg, data, httpCode...)
}

// 返回 json 带错误
func ReturnJsonWithAbort(
    ctx *gin.Context,
    success bool,
    dataCode int,
    msg string,
    data interface{},
    httpCode ...int,
) {
    New().ReturnJsonWithAbort(ctx, success, dataCode, msg, data, httpCode...)
}

// 返回成功 json
func Success(ctx *gin.Context, msg string) {
    New().Success(ctx, msg)
}

// 返回成功 json，带数据
func SuccessWithData(ctx *gin.Context, msg string, data interface{}) {
    New().SuccessWithData(ctx, msg, data)
}

// 返回错误 json
func Error(ctx *gin.Context, msg string, dataCode ...int) {
    New().Error(ctx, msg, dataCode...)
}

// 返回错误 json，带数据
func ErrorWithData(ctx *gin.Context, msg string, dataCode int, data interface{}) {
    New().ErrorWithData(ctx, msg, dataCode, data)
}

/**
 * 响应
 *
 * @create 2021-10-28
 * @author deatil
 */
type Response struct {}

/**
 * 设置 header
 */
func (this *Response) SetHeader(ctx *gin.Context, key string, value string) {
    response.New().WithContext(ctx).WithHeader(key, value)
}

/**
 * 返回字符
 */
func (this *Response) ReturnString(ctx *gin.Context, data string, httpCode ...int) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnString(data)
}

/**
 * 将json字符窜以标准json格式返回
 */
func (this *Response) ReturnJsonFromString(ctx *gin.Context, jsonStr string, httpCode ...int) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnJsonFromString(jsonStr)
}

/**
 * 返回 json
 */
func (this *Response) ReturnJson(
    ctx *gin.Context,
    success bool,
    dataCode int,
    msg string,
    data interface{},
    httpCode ...int,
) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnJson(gin.H{
        "success": success,
        "code":    dataCode,
        "message": msg,
        "data":    data,
    })
}

/**
 * 返回 json 带错误
 */
func (this *Response) ReturnJsonWithAbort(
    ctx *gin.Context,
    success bool,
    dataCode int,
    msg string,
    data interface{},
    httpCode ...int,
) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnJson(gin.H{
        "success": success,
        "code":    dataCode,
        "message": msg,
        "data":    data,
    })

    resp.Abort()
}

// 错误暂停
func (this *Response) Abort(ctx *gin.Context) {
    resp := response.New().WithContext(ctx)

    resp.Abort()
}

/**
 * 返回成功 json
 */
func (this *Response) Success(ctx *gin.Context, msg string) {
    dataCode := code.StatusSuccess

    this.ReturnJson(ctx, true, dataCode, msg, gin.H{})
}

/**
 * 返回成功 json，带数据
 */
func (this *Response) SuccessWithData(ctx *gin.Context, msg string, data interface{}) {
    dataCode := code.StatusSuccess

    this.ReturnJson(ctx, true, dataCode, msg, data)
}

/**
 * 返回错误 json
 */
func (this *Response) Error(ctx *gin.Context, msg string, dataCode ...int) {
    dataCode2 := code.StatusError
    if len(dataCode) > 0 {
        dataCode2 = dataCode[0]
    }

    this.ReturnJsonWithAbort(ctx, false, dataCode2, msg, gin.H{})
}

/**
 * 返回错误 json，带数据
 */
func (this *Response) ErrorWithData(ctx *gin.Context, msg string, dataCode int, data interface{}) {
    this.ReturnJsonWithAbort(ctx, false, dataCode, msg, data)
}

/**
 * 请求
 */
func (this *Response) Request(ctx *gin.Context) *request.Request {
    return request.New().WithContext(ctx)
}

/**
 * 响应
 */
func (this *Response) response(ctx *gin.Context) *response.Response {
    return response.New().WithContext(ctx)
}

/**
 * 下载文件
 */
func (this *Response) DownloadFile(ctx *gin.Context, filePath string, fileName string) {
    response.New().WithContext(ctx).Download(filePath, fileName)
}

