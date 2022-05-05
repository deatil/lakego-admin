package response

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/http/response"

    "github.com/deatil/lakego-doak-admin/admin/support/http/code"
)

// 使用
func New() *Response {
    resp := &Response{}

    return resp
}

// 设置 header
func SetHeader(ctx *router.Context, key string, value string) {
    New().SetHeader(ctx, key, value)
}

// 返回字符
func ReturnString(ctx *router.Context, data string, httpCode ...int) {
    New().ReturnString(ctx, data, httpCode...)
}

// 将json字符窜以标准json格式返回
func ReturnJsonFromString(ctx *router.Context, jsonStr string, httpCode ...int) {
    New().ReturnJsonFromString(ctx, jsonStr, httpCode...)
}

// 返回 json
func ReturnJson(
    ctx *router.Context,
    success bool,
    dataCode int,
    msg string,
    data any,
    httpCode ...int,
) {
    New().ReturnJson(ctx, success, dataCode, msg, data, httpCode...)
}

// 返回 json 带错误
func ReturnJsonWithAbort(
    ctx *router.Context,
    success bool,
    dataCode int,
    msg string,
    data any,
    httpCode ...int,
) {
    New().ReturnJsonWithAbort(ctx, success, dataCode, msg, data, httpCode...)
}

// 返回成功 json
func Success(ctx *router.Context, msg string) {
    New().Success(ctx, msg)
}

// 返回成功 json，带数据
func SuccessWithData(ctx *router.Context, msg string, data any) {
    New().SuccessWithData(ctx, msg, data)
}

// 返回错误 json
func Error(ctx *router.Context, msg string, dataCode ...int) {
    New().Error(ctx, msg, dataCode...)
}

// 返回错误 json，带数据
func ErrorWithData(ctx *router.Context, msg string, dataCode int, data any) {
    New().ErrorWithData(ctx, msg, dataCode, data)
}

// 返回页面
func Fetch(ctx *router.Context, template string, obj any, httpCode ...int) {
    New().Fetch(ctx, template, obj, httpCode...)
}

/**
 * JSON 响应
 *
 * @create 2021-10-28
 * @author deatil
 */
type JSONResult struct {
    Success bool         `json:"success"`
    Code    int          `json:"code"`
    Message string       `json:"message"`
    Data    any  `json:"data"`
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
func (this *Response) SetHeader(ctx *router.Context, key string, value string) {
    response.New().WithContext(ctx).WithHeader(key, value)
}

/**
 * 返回字符
 */
func (this *Response) ReturnString(ctx *router.Context, data string, httpCode ...int) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnString(data)
}

/**
 * 将json字符窜以标准json格式返回
 */
func (this *Response) ReturnJsonFromString(ctx *router.Context, jsonStr string, httpCode ...int) {
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
    ctx *router.Context,
    success bool,
    dataCode int,
    msg string,
    data any,
    httpCode ...int,
) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnJson(router.H{
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
    ctx *router.Context,
    success bool,
    dataCode int,
    msg string,
    data any,
    httpCode ...int,
) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.ReturnJson(router.H{
        "success": success,
        "code":    dataCode,
        "message": msg,
        "data":    data,
    })

    resp.Abort()
}

// 错误暂停
func (this *Response) Abort(ctx *router.Context) {
    resp := response.New().WithContext(ctx)

    resp.Abort()
}

/**
 * 返回成功 json
 */
func (this *Response) Success(ctx *router.Context, msg string) {
    dataCode := code.StatusSuccess

    this.ReturnJson(ctx, true, dataCode, msg, router.H{})
}

/**
 * 返回成功 json，带数据
 */
func (this *Response) SuccessWithData(ctx *router.Context, msg string, data any) {
    dataCode := code.StatusSuccess

    this.ReturnJson(ctx, true, dataCode, msg, data)
}

/**
 * 返回错误 json
 */
func (this *Response) Error(ctx *router.Context, msg string, dataCode ...int) {
    dataCode2 := code.StatusError
    if len(dataCode) > 0 {
        dataCode2 = dataCode[0]
    }

    this.ReturnJsonWithAbort(ctx, false, dataCode2, msg, router.H{})
}

/**
 * 返回错误 json，带数据
 */
func (this *Response) ErrorWithData(ctx *router.Context, msg string, dataCode int, data any) {
    this.ReturnJsonWithAbort(ctx, false, dataCode, msg, data)
}

/**
 * 渲染模板
 */
func (this *Response) Fetch(ctx *router.Context, template string, obj any, httpCode ...int) {
    resp := response.New().WithContext(ctx)

    if len(httpCode) > 0 {
        resp.WithHttpCode(httpCode[0])
    }

    resp.Fetch(template, obj)
}

/**
 * 下载文件
 */
func (this *Response) DownloadFile(ctx *router.Context, filePath string, fileName string) {
    response.New().WithContext(ctx).Download(filePath, fileName)
}

