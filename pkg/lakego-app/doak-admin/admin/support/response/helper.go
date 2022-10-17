package response

import (
    "github.com/deatil/lakego-doak/lakego/router"
)

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
