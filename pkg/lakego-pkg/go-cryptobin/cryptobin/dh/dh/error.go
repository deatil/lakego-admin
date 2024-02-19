package dh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this DH) AppendError(err ...error) DH {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this DH) Error() error {
    return cryptobin_tool.NewError(this.Errors...)
}
