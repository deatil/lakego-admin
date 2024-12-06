package dh

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this DH) AppendError(err ...error) DH {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this DH) Error() error {
    return errors.Join(this.Errors...)
}
