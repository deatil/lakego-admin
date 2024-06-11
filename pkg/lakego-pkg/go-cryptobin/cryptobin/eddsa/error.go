package eddsa

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this EdDSA) AppendError(err ...error) EdDSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this EdDSA) Error() error {
    return tool.NewError(this.Errors...)
}
