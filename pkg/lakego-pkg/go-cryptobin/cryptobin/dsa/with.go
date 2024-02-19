package dsa

import (
    "crypto/dsa"

    "github.com/deatil/go-cryptobin/tool"
)

// 设置 PrivateKey
func (this DSA) WithPrivateKey(data *dsa.PrivateKey) DSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this DSA) WithPublicKey(data *dsa.PublicKey) DSA {
    this.publicKey = data

    return this
}

// 设置 data
func (this DSA) WithData(data []byte) DSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this DSA) WithParedData(data []byte) DSA {
    this.parsedData = data

    return this
}

// 设置 hash 类型
func (this DSA) WithSignHash(data HashFunc) DSA {
    this.signHash = data

    return this
}

// 设置 hash 类型
// 可用参数可查看 Hash 结构体数据
func (this DSA) SetSignHash(data string) DSA {
    hash, err := tool.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置 verify
func (this DSA) WithVerify(data bool) DSA {
    this.verify = data

    return this
}

// 设置错误
func (this DSA) WithErrors(errs []error) DSA {
    this.Errors = errs

    return this
}
