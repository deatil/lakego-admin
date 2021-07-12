package exception

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/lake"
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/logger"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/response"
)

type Api struct {
    Code    int
    Message string
}

// 异常处理
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        prefix := "/" + config.New("admin").GetString("Route.Group") + "/*"

        // 只有 admin 系统路由才拦截
        if lake.MatchPath(ctx, prefix, "") {
            defer func() {
                if r := recover(); r != nil {
                    switch t := r.(type) {
                    case *Api:
                        logger.Errorf("panic: %v\n", t.Message)

                        // t.Code
                        response.Error(ctx, code.StatusException, t.Message)
                    default:
                        logger.Errorf("panic: internal error")

                        // "net/http"
                        // http.StatusInternalServerError
                        response.Error(ctx, code.StatusException, "服务器内部异常")
                    }
                }
            }()
        }

        ctx.Next()
    }
}
