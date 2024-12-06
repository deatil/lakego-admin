package elgamal

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this ElGamal) AppendError(err ...error) ElGamal {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this ElGamal) Error() error {
    return errors.Join(this.Errors...)
}
