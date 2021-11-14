package exception

import (
    "fmt"
    "runtime"
)

/**
    使用：
    import "github.com/deatil/lakego-admin/lakego/exception"

    exception.
        Try(func(){
            panic("exception error")
        }).
        Catch(func(e *exception.Exception){
            fmt.Println(e.GetMessage())
        })
*/
func Try(f func()) *Error {
    e := &Error{}
    e.Try(f)

    return e
}

/**
 * 捕获异常
 *
 * @create 2021-9-23
 * @author deatil
 */
type Error struct {
    // 运行
    tryHandler func()
}

// 运行
func (this *Error) Try(f func()) *Error {
    this.tryHandler = f

    return this
}

// 捕获
func (this *Error) Catch(f func(*Exception)) {
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

            // 存储错误信息
            e := NewException().
                WithFile(trace[3]).
                WithMessage(message).
                WithTrace(trace)

            // 传递错误信息到函数
            f(e)
        }
    }()

    tryHandle := this.tryHandler
    tryHandle()
}

// 捕获并传入 map 数据
func (this *Error) CatchMap(f func(map[string]interface{})) {
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
func (this *Error) FormatStackTrace(err interface{}) []string {
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

