package exception

import (
    "fmt"
    "runtime"
)

/**
 * 捕获异常
 * 使用：
 *    "github.com/deatil/lakego-admin/lakego/exception"
 *
 *    Try(func()).
 *        Catch(func(map[string]interface{}))
 */
func Try(f func()) *Exception {
    e := &Exception{}
    e.Try(f)

    return e
}

/**
 * 捕获异常
 *
 * @create 2021-9-23
 * @author deatil
 */
type Exception struct {
    // 运行
    tryHandler func()
}

// 运行
func (this *Exception) Try(f func()) *Exception {
    this.tryHandler = f

    return this
}

// 运行
func (this *Exception) Catch(f func(map[string]interface{})) {
    defer func() {
        if err := recover(); err != nil {

            // 错误信息
            message := ""
            switch err.(type) {
                case string:
                    message = err.(string)

                default:
                    message = fmt.Sprintf("%s", err)
            }

            trace := this.FormatStackTrace(err)

            f(map[string]interface{}{
                "file": trace[3],
                "message": message,
                "trace": trace,
            })
        }
    }()

    tryHandle := this.tryHandler
    tryHandle()
}

// 格式化堆栈信息
func (this *Exception) FormatStackTrace(err interface{}) []string {
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

