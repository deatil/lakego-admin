package elgamal

import (
    "github.com/deatil/go-cryptobin/tool"
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
)

// 设置 PrivateKey
func (this ElGamal) WithPrivateKey(data *elgamal.PrivateKey) ElGamal {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ElGamal) WithPublicKey(data *elgamal.PublicKey) ElGamal {
    this.publicKey = data

    return this
}

// 设置 hash 类型
func (this ElGamal) WithSignHash(data HashFunc) ElGamal {
    this.signHash = data

    return this
}

// 设置 hash 类型
// 可用参数可查看 Hash 结构体数据
func (this ElGamal) SetSignHash(data string) ElGamal {
    hash, err := tool.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置 data
func (this ElGamal) WithData(data []byte) ElGamal {
    this.data = data

    return this
}

// 设置 parsedData
func (this ElGamal) WithParsedData(data []byte) ElGamal {
    this.parsedData = data

    return this
}

// 设置 verify
func (this ElGamal) WithVerify(data bool) ElGamal {
    this.verify = data

    return this
}

// 设置错误
func (this ElGamal) WithErrors(errs []error) ElGamal {
    this.Errors = errs

    return this
}
