package controller

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/http/request"
    "github.com/deatil/lakego-admin/lakego/http/response"
)

/**
 * 控制器基类
 *
 * @create 2021-9-15
 * @author deatil
 */
type Base struct {}

/**
 * 设置 header
 */
func (c *Base) SetHeader(ctx *gin.Context, key string, value string) {
    response.SetHeader(ctx, key, value)
}

/**
 * 返回字符
 */
func (c *Base) ReturnString(ctx *gin.Context, data string, httpCode ...int) {
    response.ReturnString(ctx, data, httpCode...)
}

/**
 * 将json字符窜以标准json格式返回
 */
func (c *Base) ReturnJsonFromString(ctx *gin.Context, jsonStr string, httpCode ...int) {
    response.ReturnJsonFromString(ctx, jsonStr, httpCode...)
}

/**
 * 返回 json
 */
func (c *Base) ReturnJson(
    ctx *gin.Context,
    httpCode int,
    dataCode int,
    msg string,
    data interface{},
) {
    response.ReturnJson(ctx, httpCode, dataCode, msg, data)
}

/**
 * 返回成功 json
 */
func (c *Base) Success(ctx *gin.Context, msg string) {
    response.Success(ctx, msg)
}

/**
 * 返回成功 json，带数据
 */
func (c *Base) SuccessWithData(ctx *gin.Context, msg string, data interface{}) {
    response.SuccessWithData(ctx, msg, data)
}

/**
 * 返回错误 json
 */
func (c *Base) Error(ctx *gin.Context, msg string, dataCode ...int) {
    response.Error(ctx, msg, dataCode...)
}

/**
 * 返回错误 json，带数据
 */
func (c *Base) ErrorWithData(ctx *gin.Context, msg string, dataCode int, data interface{}) {
    response.ErrorWithData(ctx, msg, dataCode, data)
}

/**
 * 请求
 */
func (c *Base) Request(ctx *gin.Context) *request.ContextWrapper {
    return request.Context(ctx)
}

/**
 * 返回错误 json
 */
func (c *Base) DownloadFile(ctx *gin.Context, filePath string, fileName string) {
    response.Download(ctx, filePath, fileName)
}

