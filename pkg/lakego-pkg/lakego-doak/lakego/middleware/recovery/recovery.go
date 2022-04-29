package recovery

import (
    "fmt"
    "io"
    "os"
    "net"
    "net/http"
    "net/http/httputil"
    "time"
    "bytes"
    "runtime"
    "strings"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/logger"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

var (
    dunno     = []byte("???")
    centerDot = []byte("·")
    dot       = []byte(".")
    slash     = []byte("/")
)

/**
 * 全局异常处理
 *
 * @create 2022-3-27
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        defer func() {
            if err := recover(); err != nil {
                var brokenPipe bool
                if ne, ok := err.(*net.OpError); ok {
                    if se, ok := ne.Err.(*os.SyscallError); ok {
                        if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
                            brokenPipe = true
                        }
                    }
                }

                stack, trace := stack(3)
                httpRequest, _ := httputil.DumpRequest(ctx.Request, false)
                headers := strings.Split(string(httpRequest), "\r\n")
                for idx, header := range headers {
                    current := strings.Split(header, ":")
                    if current[0] == "Authorization" {
                        headers[idx] = current[0] + ": *"
                    }
                }

                mode := config.New("server").GetString("mode")

                var msg string

                // 提示
                switch err.(type) {
                    case string:
                        msg = err.(string)

                    default:
                        msg = fmt.Sprintf("%v", err)
                }

                // 日志数据
                logData := ""

                headersToStr := strings.Join(headers, "\r\n")
                if brokenPipe {
                    logData = fmt.Sprintf("[lakego] %s\n%s", err, headersToStr)
                } else if mode == "dev" {
                    logData = fmt.Sprintf(
                        "[lakego] panic recovered: %s\n%s\n%s",
                        err,
                        headersToStr,
                        stack,
                    )
                } else {
                    logData = fmt.Sprintf(
                        "[lakego] panic recovered: %s\n%s",
                        err,
                        stack,
                    )
                }

                // 错误输出详情
                responsedata := router.H{
                    "time": timeFormat(time.Now()),
                    "file": trace[0],
                    "trace": trace,
                }

                if mode != "dev" {
                    responsedata = router.H{}
                }

                // 记录日志
                logger.New().Error(logData)

                if brokenPipe {
                    responseData(ctx, "服务器内部异常", responsedata)
                } else {
                    responseData(ctx, msg, responsedata)
                }
            }
        }()

        ctx.Next()
    }
}

func responseData(ctx *router.Context, msg string, data router.H) {
    ctx.String(http.StatusOK, msg)
}

func stack(skip int) ([]byte, []string) {
    buf := new(bytes.Buffer)

    var errs []string

    var lines [][]byte
    var lastFile string
    for i := skip; ; i++ {
        pc, file, line, ok := runtime.Caller(i)
        if !ok {
            break
        }

        fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
        if file != lastFile {
            openFile, openErr := os.Open(file)
            if openErr != nil {
                continue
            }
            defer openFile.Close()

            data, err := io.ReadAll(openFile)
            if err != nil {
                continue
            }

            lines = bytes.Split(data, []byte{'\n'})
            lastFile = file
        }

        fmt.Fprintf(buf, "\t%s: %s\n", function(pc), source(lines, line))

        errs = append(errs, fmt.Sprintf("%s:%d (0x%x) [%s: %s]", file, line, pc, function(pc), source(lines, line)))
    }

    return buf.Bytes(), errs
}

func source(lines [][]byte, n int) []byte {
    n--
    if n < 0 || n >= len(lines) {
        return dunno
    }
    return bytes.TrimSpace(lines[n])
}

func function(pc uintptr) []byte {
    fn := runtime.FuncForPC(pc)
    if fn == nil {
        return dunno
    }
    name := []byte(fn.Name())
    if lastSlash := bytes.LastIndex(name, slash); lastSlash >= 0 {
        name = name[lastSlash+1:]
    }
    if period := bytes.Index(name, dot); period >= 0 {
        name = name[period+1:]
    }

    name = bytes.Replace(name, centerDot, dot, -1)
    return name
}

// 时间格式化
func timeFormat(t time.Time) string {
    timeString := t.Format("2006-01-02 15:04:05")
    return timeString
}
