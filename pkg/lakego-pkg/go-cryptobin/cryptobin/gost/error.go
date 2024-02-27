package gost

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Gost) AppendError(err ...error) Gost {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Gost) Error() error {
    return tool.NewError(this.Errors...)
}
