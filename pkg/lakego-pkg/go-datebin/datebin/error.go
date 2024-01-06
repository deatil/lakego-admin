package datebin

import (
    "errors"
)

// 添加错误
// append error
func (this Datebin) AppendError(err ...error) Datebin {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
// output errors
func (this Datebin) Error() error {
    return errors.Join(this.Errors...)
}
