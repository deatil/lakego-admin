package bign

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/hash"
    "github.com/deatil/go-cryptobin/pubkey/bign"
    ecbign "github.com/deatil/go-cryptobin/elliptic/bign"
)

// 设置 PrivateKey
func (this Bign) WithPrivateKey(data *bign.PrivateKey) Bign {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Bign) WithPublicKey(data *bign.PublicKey) Bign {
    this.publicKey = data

    return this
}

// 设置曲线类型
func (this Bign) WithCurve(curve elliptic.Curve) Bign {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选 [Bign256v1 | Bign384v1 | Bign512v1]
func (this Bign) SetCurve(curve string) Bign {
    switch curve {
        case "Bign256v1":
            this.curve = ecbign.P256v1()
        case "Bign384v1":
            this.curve = ecbign.P384v1()
        case "Bign512v1":
            this.curve = ecbign.P512v1()
    }

    return this
}

// 设置 hash 类型
func (this Bign) WithSignHash(hash HashFunc) Bign {
    this.signHash = hash

    return this
}

// 设置 hash 类型
func (this Bign) SetSignHash(name string) Bign {
    h, err := hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = h

    return this
}

// 设置 data
func (this Bign) WithData(data []byte) Bign {
    this.data = data

    return this
}

// 设置 adata
func (this Bign) WithAdata(adata []byte) Bign {
    this.adata = adata

    return this
}

// 设置 parsedData
func (this Bign) WithParsedData(data []byte) Bign {
    this.parsedData = data

    return this
}

// 设置编码方式
func (this Bign) WithEncoding(encoding EncodingType) Bign {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this Bign) WithEncodingASN1() Bign {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this Bign) WithEncodingBytes() Bign {
    return this.WithEncoding(EncodingBytes)
}

// 设置验证结果
func (this Bign) WithVerify(data bool) Bign {
    this.verify = data

    return this
}

// 设置错误
func (this Bign) WithErrors(errs []error) Bign {
    this.Errors = errs

    return this
}
