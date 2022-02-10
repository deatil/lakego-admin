package exception

import (
    "os"
    "net"
    "fmt"
    "time"
    "strings"
    "runtime"
    "runtime/debug"

    "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/facade/logger"
    "github.com/deatil/lakego-admin/lakego/facade/config"

    "github.com/deatil/lakego-admin/admin/support/response"
    "github.com/deatil/lakego-admin/admin/support/http/code"
)

/**
 * 异常处理
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        defer func() {
            if r := recover(); r != nil {
                var brokenPipe bool
                if ne, ok := r.(*net.OpError); ok {
                    if se, ok := ne.Err.(*os.SyscallError); ok {
                        if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
                            brokenPipe = true
                        }
                    }
                }

                mode := config.New("server").GetString("Mode")
                if mode == "lakegodev" || mode == "dev" {

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

                    trace := formatStackTrace()

                    // 错误输出详情
                    responsedata := router.H{
                        "time": time,
                        "file": trace[3],
                        "trace": trace,
                    }

                    switch r.(type) {
                        case string:
                            logger.New().Errorf("%s | panic: %s\n", logStr, r.(string))

                            // 输出日志
                            response.ErrorWithData(ctx, r.(string), code.StatusException, responsedata)

                        default:
                            logger.New().Errorf("%s | panic: internal error. message: %s, stack: %v", logStr, r, string(debug.Stack()))

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
                            logger.New().Errorf("%s | panic: %s\n", logStr, r.(string))

                            // 输出日志
                            response.Error(ctx, r.(string), code.StatusException)

                        default:
                            logger.New().Errorf("%s | panic: internal error. message: %s, stack: %v", logStr, r, string(debug.Stack()))

                            response.Error(ctx, "服务器内部异常", code.StatusException)
                    }

                }

                if brokenPipe {
                    ctx.Error(r.(error))
                    ctx.Abort()
                }
            }
        }()

        ctx.Next()
    }
}

// 格式化堆栈信息
func formatStackTrace() []string {
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
