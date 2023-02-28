package dh

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Dh) AppendError(err ...error) Dh {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Dh) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
