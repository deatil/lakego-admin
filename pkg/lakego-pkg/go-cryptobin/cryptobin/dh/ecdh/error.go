package ecdh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Ecdh) AppendError(err ...error) Ecdh {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Ecdh) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
