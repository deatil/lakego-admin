package bign

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Bign) AppendError(err ...error) Bign {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Bign) Error() error {
    return tool.NewError(this.Errors...)
}
