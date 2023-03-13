package datebin

import (
    "github.com/deatil/go-datebin/errors"
)

// 添加错误
func (this Datebin) AppendError(err ...error) Datebin {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Datebin) Error() error {
    return errors.New(this.Errors...)
}
