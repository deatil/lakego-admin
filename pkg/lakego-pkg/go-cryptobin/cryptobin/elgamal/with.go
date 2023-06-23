package elgamal

import (
    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/elgamal"
)

// 设置 PrivateKey
func (this EIGamal) WithPrivateKey(data *elgamal.PrivateKey) EIGamal {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this EIGamal) WithPublicKey(data *elgamal.PublicKey) EIGamal {
    this.publicKey = data

    return this
}

// 设置 hash 类型
func (this EIGamal) WithSignHash(data HashFunc) EIGamal {
    this.signHash = data

    return this
}

// 设置 hash 类型
// 可用参数可查看 Hash 结构体数据
func (this EIGamal) SetSignHash(data string) EIGamal {
    hash, err := tool.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置 data
func (this EIGamal) WithData(data []byte) EIGamal {
    this.data = data

    return this
}

// 设置 paredData
func (this EIGamal) WithParedData(data []byte) EIGamal {
    this.paredData = data

    return this
}

// 设置 verify
func (this EIGamal) WithVerify(data bool) EIGamal {
    this.verify = data

    return this
}

// 设置错误
func (this EIGamal) WithErrors(errs []error) EIGamal {
    this.Errors = errs

    return this
}
