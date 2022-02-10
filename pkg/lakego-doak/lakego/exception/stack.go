package exception

import (
    "fmt"
)

// 构造函数
func NewStack(file string, line int, pc interface{}) Stack {
    stack := Stack{
        File: file,
        Line: line,
        Pc: pc,
    }

    return stack
}

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
    Pc interface{}
}

// 添加文件
func (this Stack) GetFile() string {
    return this.File
}

// 添加行数
func (this Stack) GetLine() int {
    return this.Line
}

// 添加 PC
func (this Stack) GetPc() interface{} {
    return this.Pc
}

// 输出堆栈信息
func (this *Stack) String() string {
    data := fmt.Sprintf("%s:%d (0x%x)", this.File, this.Line, this.Pc)

    return data
}

