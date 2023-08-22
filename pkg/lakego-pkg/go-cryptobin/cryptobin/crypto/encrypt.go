package crypto

import (
    "fmt"
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
        err := fmt.Errorf("Cryptobin: Multiple [%s] is error.", m)
        return nil, err
    }

    // 类型
    newEncrypt := UseEncrypt.Get(m)

    return newEncrypt(), nil
}

// 加密
func (this Cryptobin) Encrypt() Cryptobin {
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
func (this Cryptobin) FuncEncrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this).triggerError()
}

// 方法解密
func (this Cryptobin) FuncDecrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this).triggerError()
}
