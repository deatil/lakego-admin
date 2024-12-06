package curve25519

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this Curve25519) AppendError(err ...error) Curve25519 {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Curve25519) Error() error {
    return errors.Join(this.Errors...)
}
