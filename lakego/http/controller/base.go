package controller

import (
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/http/response"
)

type BaseController struct {

}

/**
 * 设置 header
 */
func (c *BaseController) SetHeader(context *gin.Context, key string, value string) {
    response.SetHeader(context, key, value)
}

/**
 * 返回 json
 */
func (c *BaseController) ReturnJson(
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
func (c *BaseController) Success(context *gin.Context, msg string) {
    response.Success(context, msg)
}

/**
 * 返回成功 json，带数据
 */
func (c *BaseController) SuccessWithData(context *gin.Context, msg string, data interface{}) {
    response.SuccessWithData(context, msg, data)
}

/**
 * 返回错误 json
 */
func (c *BaseController) Error(context *gin.Context, dataCode int, msg string) {
    response.Error(context, dataCode, msg)
}

/**
 * 返回错误 json，带数据
 */
func (c *BaseController) ErrorWithData(context *gin.Context, dataCode int, msg string, data interface{}) {
    response.ErrorWithData(context, dataCode, msg, data)
}

