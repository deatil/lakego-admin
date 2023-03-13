package rsa

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Rsa) AppendError(err ...error) Rsa {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Rsa) Error() error {
    return cryptobin_tool.NewError(this.Errors...)
}
