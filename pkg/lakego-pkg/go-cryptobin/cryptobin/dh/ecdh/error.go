package ecdh

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this ECDH) AppendError(err ...error) ECDH {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this ECDH) Error() error {
    return tool.NewError(this.Errors...)
}
