package sm2

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this SM2) AppendError(errs ...error) SM2 {
    this.Errors = append(this.Errors, errs...)

    return this
}

// 获取错误
func (this SM2) Error() error {
    return cryptobin_tool.NewError(this.Errors...)
}
