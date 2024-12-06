package rsa

import (
    "hash"
    "crypto"
    "crypto/rsa"

    tool_hash "github.com/deatil/go-cryptobin/tool/hash"
)

// 设置 PrivateKey
func (this RSA) WithPrivateKey(data *rsa.PrivateKey) RSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this RSA) WithPublicKey(data *rsa.PublicKey) RSA {
    this.publicKey = data

    return this
}

// 设置 hash 类型
func (this RSA) WithSignHash(h crypto.Hash) RSA {
    this.signHash = h

    return this
}

// 设置 hash 类型
func (this RSA) SetSignHash(name string) RSA {
    newHash, err := tool_hash.GetCryptoHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = newHash

    return this
}

// 设置 OAEP Hash
func (this RSA) WithOAEPHash(h hash.Hash) RSA {
    this.oaepHash = h

    return this
}

// 设置 OAEP Hash 类型
func (this RSA) SetOAEPHash(name string) RSA {
    newHash, err := tool_hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.oaepHash = newHash()

    return this
}

// 设置 OAEP Label
func (this RSA) WithOAEPLabel(data []byte) RSA {
    this.oaepLabel = data

    return this
}

// 设置 OAEP Label
func (this RSA) SetOAEPLabel(data string) RSA {
    this.oaepLabel = []byte(data)

    return this
}

// 设置 keyData
func (this RSA) WithKeyData(data []byte) RSA {
    this.keyData = data

    return this
}

// 设置 keyData
func (this RSA) SetKeyData(data string) RSA {
    this.keyData = []byte(data)

    return this
}

// 设置 data
func (this RSA) WithData(data []byte) RSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this RSA) WithParsedData(data []byte) RSA {
    this.parsedData = data

    return this
}

// 设置 verify
func (this RSA) WithVerify(data bool) RSA {
    this.verify = data

    return this
}

// 设置错误
func (this RSA) WithError(errs []error) RSA {
    this.Errors = errs

    return this
}
