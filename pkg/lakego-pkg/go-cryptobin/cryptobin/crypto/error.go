package crypto

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this Cryptobin) AppendError(err ...error) Cryptobin {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this Cryptobin) Error() error {
    return tool.NewError(this.Errors...)
}
