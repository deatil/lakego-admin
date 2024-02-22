package ed448

import (
    "crypto"
    "github.com/deatil/go-cryptobin/ed448"
)

// 设置 PrivateKey
func (this ED448) WithPrivateKey(data ed448.PrivateKey) ED448 {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ED448) WithPublicKey(data ed448.PublicKey) ED448 {
    this.publicKey = data

    return this
}

// 设置 options
func (this ED448) WithOptions(op *Options) ED448 {
    this.options = op

    return this
}

// 设置 options
// 可用类型 [ED448Ph | ED448]
func (this ED448) SetOptions(name string, context ...string) ED448 {
    ctx := ""
    if len(context) > 0 {
        ctx = context[0]
    }

    switch name {
        case "ED448Ph":
            this.options = &Options{
                Hash:    crypto.Hash(0),
                Context: ctx,
                Scheme:  ed448.ED448Ph,
            }
        case "ED448":
            this.options = &Options{
                Hash:    crypto.Hash(0),
                Context: ctx,
                Scheme:  ed448.ED448,
            }
    }

    return this
}

// 设置 data
func (this ED448) WithData(data []byte) ED448 {
    this.data = data

    return this
}

// 设置 parsedData
func (this ED448) WithParsedData(data []byte) ED448 {
    this.parsedData = data

    return this
}

// 设置 verify
func (this ED448) WithVerify(data bool) ED448 {
    this.verify = data

    return this
}

// 设置错误
func (this ED448) WithErrors(errs []error) ED448 {
    this.Errors = errs

    return this
}
