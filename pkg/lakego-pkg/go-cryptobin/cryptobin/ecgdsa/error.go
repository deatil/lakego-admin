package ecgdsa

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this ECGDSA) AppendError(err ...error) ECGDSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this ECGDSA) Error() error {
    return errors.Join(this.Errors...)
}
