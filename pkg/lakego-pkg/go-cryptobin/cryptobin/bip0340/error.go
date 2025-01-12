package bip0340

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this BIP0340) AppendError(err ...error) BIP0340 {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this BIP0340) Error() error {
    return errors.Join(this.Errors...)
}
