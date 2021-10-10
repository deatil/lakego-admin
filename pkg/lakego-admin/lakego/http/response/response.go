package response

import (
    "net/http"

    "github.com/gin-gonic/gin"
)

// 设置 header
func SetHeader(ctx *gin.Context, key string, value string) {
    ctx.Header(key, value)
}

// 批量设置 header
func SetHeaders(ctx *gin.Context, headers map[string]string) {
    if len(headers) > 0 {
        for k, v := range headers {
            ctx.Header(k, v)
        }
    }
}

// 返回字符
func ReturnString(ctx *gin.Context, contents string, httpCode ...int) {
    code := http.StatusOK
    if len(httpCode) > 0 {
        code = httpCode[0]
    }

    ctx.String(code, contents)
}

// 将json字符窜以标准json格式返回（例如，从redis读取json、格式的字符串，返回给浏览器json格式）
func ReturnJsonFromString(ctx *gin.Context, jsonStr string, httpCode ...int) {
    code := http.StatusOK
    if len(httpCode) > 0 {
        code = httpCode[0]
    }

    ctx.Header("Content-Type", "application/json; charset=utf-8")
    ctx.String(code, jsonStr)
}

// 返回 json
func ReturnJson(
    ctx *gin.Context,
    httpCode int,
    dataCode int,
    msg string,
    data interface{},
) {
    // ctx.Header("key", "value")
    ctx.JSON(httpCode, gin.H{
        "code":    dataCode,
        "message": msg,
        "data":    data,
    })
}

// 直接返回成功
func Success(ctx *gin.Context, msg string, dataCode int) {
    ReturnJson(ctx, http.StatusOK, dataCode, msg, gin.H{})
}

// 直接返回成功，带数据
func SuccessWithData(ctx *gin.Context, msg string, data interface{}, dataCode int) {
    ReturnJson(ctx, http.StatusOK, dataCode, msg, data)
}

// 失败的业务逻辑
func Error(ctx *gin.Context, msg string, dataCode int) {
    ReturnJson(ctx, http.StatusOK, dataCode, msg, gin.H{})
    ctx.Abort()
}

// 失败的业务逻辑，带业务代码
func ErrorWithCode(ctx *gin.Context, msg string, dataCode int) {
    ReturnJson(ctx, http.StatusOK, dataCode, msg, gin.H{})
    ctx.Abort()
}

// 失败的业务逻辑，带数据
func ErrorWithData(ctx *gin.Context, msg string, dataCode int, data interface{}) {
    ReturnJson(ctx, http.StatusOK, dataCode, msg, data)
    ctx.Abort()
}

// 下载
func Download(ctx *gin.Context, filePath string, fileName string) {
    ctx.Header("Content-Type", "application/octet-stream")
    ctx.Header("Content-Disposition", "attachment; filename="+fileName)
    ctx.Header("Content-Transfer-Encoding", "binary")
    ctx.File(filePath)
}
