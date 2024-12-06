package sm2

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this SM2) AppendError(errs ...error) SM2 {
    this.Errors = append(this.Errors, errs...)

    return this
}

// 获取错误
func (this SM2) Error() error {
    return errors.Join(this.Errors...)
}
