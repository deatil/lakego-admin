package crypto

import (
    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Cryptobin) AppendError(err ...error) Cryptobin {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Cryptobin) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
}
