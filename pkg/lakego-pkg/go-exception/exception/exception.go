package exception

// 构造函数
func NewException(
    code int,
    message string,
    file string,
    line int,
    trace []Stack,
) Exception {
    e := Exception{
        Code: code,
        File: file,
        Line: line,
        Message: message,
        Trace: trace,
    }

    return e
}

// 构造函数
func NewExceptionWithMessage(
    message string,
    code ...int,
) Exception {
    e := Exception{
        Message: message,
    }

    if len(code) > 0 {
        e.Code = code[0]
    } else {
        e.Code = 500
    }

    return e
}

/**
 * 异常
 *
 * @create 2021-11-13
 * @author deatil
 */
type Exception struct {
    // 状态码
    Code int

    // 错误信息
    Message string

    // 文件
    File string

    // 文件行
    Line int

    // 堆栈信息
    Trace []Stack
}

// 获取状态码
func (this Exception) GetCode() int {
    return this.Code
}

// 获取错误信息
func (this Exception) GetMessage() string {
    return this.Message
}

// 获取文件信息
func (this Exception) GetFile() string {
    return this.File
}

// 获取文件行
func (this Exception) GetLine() int {
    return this.Line
}

// 获取堆栈信息
func (this Exception) GetTrace() []Stack {
    return this.Trace
}

// 默认返回
func (this Exception) String() string {
    return this.Message
}

