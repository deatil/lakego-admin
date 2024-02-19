package ecdsa

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this ECDSA) AppendError(err ...error) ECDSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this ECDSA) Error() error {
    return cryptobin_tool.NewError(this.Errors...)
}
