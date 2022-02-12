package exception

import (
    "io"
    "os"
    "fmt"
    "bytes"
    "runtime"
)

// 构造函数
func NewStack(file string, line int, pc uintptr) Stack {
    stack := Stack{
        File: file,
        Line: line,
        Pc: pc,
    }

    return stack
}

var (
    dunno     = []byte("???")
    centerDot = []byte("·")
    dot       = []byte(".")
    slash     = []byte("/")
)

/**
 * 栈
 *
 * @create 2022-2-5
 * @author deatil
 */
type Stack struct {
    // 文件
    File string

    // 行数
    Line int

    // pc
    Pc uintptr
}

// 文件
func (this Stack) GetFile() string {
    return this.File
}

// 行数
func (this Stack) GetLine() int {
    return this.Line
}

// PC
func (this Stack) GetPc() uintptr {
    return this.Pc
}

// PC
func (this Stack) GetFuncForPC() string {
    fn := runtime.FuncForPC(this.Pc)
    if fn == nil {
        return ""
    }

    return fn.Name()
}

// Source
func (this Stack) GetSource() string {
    var lines [][]byte

    openFile, openErr := os.Open(this.File)
    if openErr != nil {
        return ""
    }
    defer openFile.Close()

    data, err := io.ReadAll(openFile)
    if err != nil {
        return ""
    }

    lines = bytes.Split(data, []byte{'\n'})

    info := fmt.Sprintf("%s", this.FormatSource(lines, this.Line))

    return info
}

// Function
func (this Stack) GetFunction() string {
    info := fmt.Sprintf("%s", this.FormatFunction(this.Pc))

    return info

}

// 输出堆栈信息
func (this *Stack) String() string {
    data := fmt.Sprintf("%s:%d (0x%x)", this.File, this.Line, this.Pc)

    return data
}

// 长数据信息
func (this *Stack) LongString() string {
    file, line, pc := this.File, this.Line, this.Pc

    info := fmt.Sprintf(
        "%s:%d (0x%x) [%s: %s]",
        file, line, pc,
        this.GetFunction(), this.GetSource(),
    )

    return info
}

// 格式化
func (this *Stack) FormatFunction(pc uintptr) []byte {
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

// 格式化
func (this *Stack) FormatSource(lines [][]byte, n int) []byte {
    n--

    if n < 0 || n >= len(lines) {
        return dunno
    }

    return bytes.TrimSpace(lines[n])
}

