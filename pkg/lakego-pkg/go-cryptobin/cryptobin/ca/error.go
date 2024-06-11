package ca

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this CA) AppendError(err ...error) CA {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this CA) Error() error {
    return tool.NewError(this.Errors...)
}
