package response

import (
	"net/http"
	
	"github.com/gin-gonic/gin"
	
	"lakego-admin/lakego/http/code"
)

// 设置 header
func SetHeader(context *gin.Context, key string, value string) {
	context.Header(key, value)
}

func ReturnJson(
	context *gin.Context, 
	httpCode int, 
	dataCode int, 
	msg string, 
	data interface{},
) {
	// context.Header("key", "value")
	context.JSON(httpCode, gin.H{
		"code":    dataCode,
		"message": msg,
		"data":    data,
	})
}

// 将json字符窜以标准json格式返回（例如，从redis读取json、格式的字符串，返回给浏览器json格式）
func ReturnJsonFromString(context *gin.Context, httpCode int, jsonStr string) {
	context.Header("Content-Type", "application/json; charset=utf-8")
	context.String(httpCode, jsonStr)
}

// 直接返回成功
func Success(c *gin.Context, msg string) {
	ReturnJson(c, http.StatusOK, code.StatusSuccess, msg, gin.H{})
}

// 直接返回成功，带数据
func SuccessWithData(c *gin.Context, msg string, data interface{}) {
	ReturnJson(c, http.StatusOK, code.StatusSuccess, msg, data)
}

// 失败的业务逻辑
func Error(c *gin.Context, dataCode int, msg string) {
	ReturnJson(c, http.StatusOK, dataCode, msg, gin.H{})
	c.Abort()
}

// 失败的业务逻辑，带数据
func ErrorWithData(c *gin.Context, dataCode int, msg string, data interface{}) {
	ReturnJson(c, http.StatusOK, dataCode, msg, data)
	c.Abort()
}
