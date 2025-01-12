package ecsdsa

import (
    "github.com/deatil/go-cryptobin/tool/errors"
)

// 添加错误
func (this ECSDSA) AppendError(err ...error) ECSDSA {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this ECSDSA) Error() error {
    return errors.Join(this.Errors...)
}
