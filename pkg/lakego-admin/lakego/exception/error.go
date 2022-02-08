package exception

import (
    "fmt"
    "runtime"
)

// 抛出异常
func Throw(message string, code ...int) {
    exception := NewException().WithMessage(message)
    if len(code) > 0 {
        exception.WithCode(code[0])
    }

    panic(exception)
}

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
    handler func()
}

// 运行
func (this *Error) Try(f func()) *Error {
    this.handler = f

    return this
}

// 捕获
func (this *Error) Catch(f func(*Exception)) {
    defer func() {
        if err := recover(); err != nil {

            // 错误信息
            code := 500
            message := ""

            // 判断
            switch err.(type) {
                case *Exception:
                    err2 := err.(*Exception)
                    code = err2.GetCode()
                    message = err2.GetMessage()

                case string:
                    message = err.(string)

                default:
                    message = fmt.Sprintf("%+v", err)
            }

            // 获取堆栈信息
            traces := this.GetStackTrace()

            // 当前栈
            nowStack := traces[3]

            // 存储错误信息
            e := NewException().
                WithCode(code).
                WithFile(nowStack.GetFile()).
                WithLine(nowStack.GetLine()).
                WithMessage(message).
                WithTrace(traces)

            // 传递错误信息到函数
            f(e)
        }
    }()

    tryHandler := this.handler
    tryHandler()
}

// 获取堆栈信息
func (this *Error) GetStackTrace() []Stack {
    errs := make([]Stack, 0)

    for i := 1; ; i++ {
        pc, file, line, ok := runtime.Caller(i)
        if !ok {
            break
        }

        errs = append(errs, NewStack(file, line, pc))
    }

    return errs
}

