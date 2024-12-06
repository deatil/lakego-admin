package crypto

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
// Append Error
func (this Cryptobin) AppendError(err ...error) Cryptobin {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
// get error
func (this Cryptobin) Error() error {
    return errors.Join(this.Errors...)
}
