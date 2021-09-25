package exception

import (
    "fmt"
    "time"
    "runtime"
    "runtime/debug"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/logger"
    "lakego-admin/lakego/http/response"
    "lakego-admin/lakego/facade/config"

    "lakego-admin/admin/support/http/code"
)

// 异常处理
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        defer func() {
            if r := recover(); r != nil {
                mode := config.New("admin").GetString("Mode")
                if mode == "dev" {

                    time := time.Now()
                    path := ctx.Request.URL.Path
                    raw := ctx.Request.URL.RawQuery

                    clientIP := ctx.ClientIP()
                    method := ctx.Request.Method
                    selecttatusCode := ctx.Writer.Status()
                    bodySize := ctx.Writer.Size()

                    if raw != "" {
                        path = path + "?" + raw
                    }

                    logStr := fmt.Sprintf(
                        "[%d][%s]%s:%s %d",
                        selecttatusCode,
                        clientIP,
                        method,
                        path,
                        bodySize,
                    )

                    trace := formatStackTrace(r)

                    // 错误输出详情
                    responsedata := gin.H{
                        "time": time,
                        "file": trace[3],
                        "trace": trace,
                    }

                    switch r.(type) {
                        case string:
                            logger.Errorf("%s | panic: %s\n", logStr, r.(string))

                            // 输出日志
                            response.ErrorWithData(ctx, r.(string), code.StatusException, responsedata)

                        default:
                            logger.Errorf("%s | panic: internal error. message: %s, stack: %v", logStr, r, string(debug.Stack()))

                            // "net/http"
                            // http.StatusInternalServerError
                            response.ErrorWithData(ctx, fmt.Sprintf("%v", r), code.StatusException, responsedata)
                    }

                } else {

                    path := ctx.Request.URL.Path
                    raw := ctx.Request.URL.RawQuery

                    clientIP := ctx.ClientIP()
                    method := ctx.Request.Method
                    selecttatusCode := ctx.Writer.Status()

                    if raw != "" {
                        path = path + "?" + raw
                    }

                    logStr := fmt.Sprintf(
                        "[%d][%s]%s:%s",
                        selecttatusCode,
                        clientIP,
                        method,
                        path,
                    )

                    switch r.(type) {
                        case string:
                            logger.Errorf("%s | panic: %s\n", logStr, r.(string))

                            // 输出日志
                            response.Error(ctx, r.(string), code.StatusException)

                        default:
                            logger.Errorf("%s | panic: internal error. message: %s, stack: %v", logStr, r, string(debug.Stack()))

                            // "net/http"
                            // http.StatusInternalServerError
                            response.Error(ctx, "服务器内部异常", code.StatusException)
                    }

                }

            }
        }()

        ctx.Next()
    }
}

// 格式化堆栈信息
func formatStackTrace(err interface{}) []string {
    errs := make([]string, 0)

    for i := 1; ; i++ {
        pc, file, line, ok := runtime.Caller(i)
        if !ok {
            break
        }

        errs = append(errs, fmt.Sprintf("%s:%d (0x%x)", file, line, pc))
    }

    return errs
}
