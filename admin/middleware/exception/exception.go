package exception

import (
    "runtime/debug"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/logger"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/response"
)

// 异常处理
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        defer func() {
            if r := recover(); r != nil {
                switch r.(type) {
                case string:
                    logger.Errorf("panic: %v\n", r.(string))

                    // 输出日志
                    response.Error(ctx, code.StatusException, r.(string))
                default:
                    logger.Errorf("panic: internal error. stack: %v", string(debug.Stack()))

                    // "net/http"
                    // http.StatusInternalServerError
                    response.Error(ctx, code.StatusException, "服务器内部异常")
                }
            }
        }()

        ctx.Next()
    }
}
