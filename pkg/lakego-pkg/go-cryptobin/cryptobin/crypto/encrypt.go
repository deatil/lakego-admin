package crypto

import (
    "fmt"

    "github.com/deatil/go-cryptobin/tool"
)

// 加密解密
var UseEncrypt = NewDataSet[Multiple, IEncrypt]()

// 模式
var UseMode = NewDataSet[Mode, IMode]()

// 补码
var UsePadding = NewDataSet[Padding, IPadding]()

// 获取加密解密方式
func getEncrypt(m Multiple) (IEncrypt, error) {
    if !UseEncrypt.Has(m) {
        err := fmt.Errorf("Multiple [%s] is error.", m)
        return nil, err
    }

    // 类型
    newEncrypt := UseEncrypt.Get(m)

    return newEncrypt(), nil
}

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
    err := tool.Recover(func() {
        this = this.encrypt()
    })

    if err != nil {
        return this.AppendError(err).triggerError()
    }

    return this
}

// 加密
func (this Cryptobin) encrypt() Cryptobin {
    // 加密解密
    newEncrypt, err := getEncrypt(this.multiple)
    if err != nil {
        return this.AppendError(err).triggerError()
    }

    dst, err := newEncrypt.Encrypt(this.data, NewConfig(this))
    if err != nil {
        return this.AppendError(err).triggerError()
    }

    this.parsedData = dst

    return this.triggerError()
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    err := tool.Recover(func() {
        this = this.decrypt()
    })

    if err != nil {
        return this.AppendError(err).triggerError()
    }

    return this
}

// 解密
func (this Cryptobin) decrypt() Cryptobin {
    // 加密解密
    newEncrypt, err := getEncrypt(this.multiple)
    if err != nil {
        return this.AppendError(err).triggerError()
    }

    dst, err := newEncrypt.Decrypt(this.data, NewConfig(this))
    if err != nil {
        return this.AppendError(err).triggerError()
    }

    this.parsedData = dst

    return this.triggerError()
}

// ====================

// 方法加密
func (this Cryptobin) FuncEncrypt(fn func(Cryptobin) Cryptobin) Cryptobin {
    err := tool.Recover(func() {
        this = fn(this).triggerError()
    })

    if err != nil {
        return this.AppendError(err).triggerError()
    }

    return this
}

// 方法解密
func (this Cryptobin) FuncDecrypt(fn func(Cryptobin) Cryptobin) Cryptobin {
    err := tool.Recover(func() {
        this = fn(this).triggerError()
    })

    if err != nil {
        return this.AppendError(err).triggerError()
    }

    return this
}
