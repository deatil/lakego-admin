package curve25519

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Curve25519) AppendError(err ...error) Curve25519 {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Curve25519) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
