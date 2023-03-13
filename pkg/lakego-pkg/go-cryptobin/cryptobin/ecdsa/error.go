package ecdsa

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Ecdsa) AppendError(err ...error) Ecdsa {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Ecdsa) Error() error {
    return cryptobin_tool.NewError(this.Errors...)
}
