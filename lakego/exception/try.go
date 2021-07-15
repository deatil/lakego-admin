package exception

import (
    "bytes"
    "fmt"
    "runtime"
)

/**
* 捕获异常try...catch
* 用法示例：
  defer try.CatchException(func(e interface{}) {
      log.Println(e)
  })
*/
func CatchException(handle func(e interface{})) {
    if err := recover(); err != nil {
        e := printStackTrace(err)
        handle(e)
    }
}

// 打印堆栈信息
func printStackTrace(err interface{}) string {
    buf := new(bytes.Buffer)

    fmt.Fprintf(buf, "%v\n", err)

    for i := 1; ; i++ {
        pc, file, line, ok := runtime.Caller(i)
        if !ok {
            break
        }

        fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
    }

    return buf.String()
}

