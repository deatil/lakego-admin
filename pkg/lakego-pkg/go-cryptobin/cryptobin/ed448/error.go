package ed448

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this ED448) AppendError(err ...error) ED448 {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this ED448) Error() error {
    return errors.Join(this.Errors...)
}
