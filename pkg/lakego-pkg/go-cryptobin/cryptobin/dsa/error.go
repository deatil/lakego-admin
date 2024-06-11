package dsa

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this DSA) AppendError(err ...error) DSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this DSA) Error() error {
    return tool.NewError(this.Errors...)
}
