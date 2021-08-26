package controller

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/http/response"
)

type Base struct {

}

/**
 * 设置 header
 */
func (c *Base) SetHeader(context *gin.Context, key string, value string) {
    response.SetHeader(context, key, value)
}

/**
 * 返回 json
 */
func (c *Base) ReturnJson(
    context *gin.Context,
    httpCode int,
    dataCode int,
    msg string,
    data interface{},
) {
    response.ReturnJson(context, httpCode, dataCode, msg, data)
}

/**
 * 返回成功 json
 */
func (c *Base) Success(context *gin.Context, msg string) {
    response.Success(context, msg)
}

/**
 * 返回成功 json，带数据
 */
func (c *Base) SuccessWithData(context *gin.Context, msg string, data interface{}) {
    response.SuccessWithData(context, msg, data)
}

/**
 * 返回错误 json
 */
func (c *Base) Error(context *gin.Context, msg string, dataCode ...int) {
    response.Error(context, msg, dataCode...)
}

/**
 * 返回错误 json，带数据
 */
func (c *Base) ErrorWithData(context *gin.Context, msg string, dataCode int, data interface{}) {
    response.ErrorWithData(context, msg, dataCode, data)
}

