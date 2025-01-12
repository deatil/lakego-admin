package ecgdsa

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this SSH) AppendError(err ...error) SSH {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this SSH) Error() error {
    return errors.Join(this.Errors...)
}
