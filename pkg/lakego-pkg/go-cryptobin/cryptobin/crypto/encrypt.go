package crypto

import (
    "fmt"
)

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
        return this.AppendError(err)
    }

    dst, err := newEncrypt.Encrypt(this.data, NewConfig(this))
    if err != nil {
        return this.AppendError(err)
    }

    // 补码模式
    this.parsedData = dst

    return this
}

// 解密
func (this Cryptobin) Decrypt() Cryptobin {
    // 加密解密
    newEncrypt, err := getEncrypt(this.multiple)
    if err != nil {
        return this.AppendError(err)
    }

    dst, err := newEncrypt.Decrypt(this.data, NewConfig(this))
    if err != nil {
        return this.AppendError(err)
    }

    // 补码模式
    this.parsedData = dst

    return this
}

// ====================

// 方法加密
func (this Cryptobin) FuncEncrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this)
}

// 方法解密
func (this Cryptobin) FuncDecrypt(f func(Cryptobin) Cryptobin) Cryptobin {
    return f(this)
}
