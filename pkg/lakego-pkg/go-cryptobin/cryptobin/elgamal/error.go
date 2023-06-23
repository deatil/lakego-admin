package elgamal

import (
    "github.com/deatil/go-cryptobin/tool"
)

// 添加错误
func (this EIGamal) AppendError(err ...error) EIGamal {
    this.Errors = append(this.Errors, err...)

    return this
}

// 获取错误
func (this EIGamal) Error() error {
    return tool.NewError(this.Errors...)
}
