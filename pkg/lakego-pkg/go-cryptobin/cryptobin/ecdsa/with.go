package ecdsa

import (
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/hash"
)

// 设置 PrivateKey
func (this ECDSA) WithPrivateKey(data *ecdsa.PrivateKey) ECDSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ECDSA) WithPublicKey(data *ecdsa.PublicKey) ECDSA {
    this.publicKey = data

    return this
}

// 设置曲线类型
func (this ECDSA) WithCurve(curve elliptic.Curve) ECDSA {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选参数 [P521 | P384 | P256 | P224]
func (this ECDSA) SetCurve(curve string) ECDSA {
    switch curve {
        case "P521":
            this.curve = elliptic.P521()
        case "P384":
            this.curve = elliptic.P384()
        case "P256":
            this.curve = elliptic.P256()
        case "P224":
            this.curve = elliptic.P224()
    }

    return this
}

// 设置 hash 类型
func (this ECDSA) WithSignHash(hash HashFunc) ECDSA {
    this.signHash = hash

    return this
}

// 设置 hash 类型
func (this ECDSA) SetSignHash(name string) ECDSA {
    h, err := hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = h

    return this
}

// 设置 data
func (this ECDSA) WithData(data []byte) ECDSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this ECDSA) WithParsedData(data []byte) ECDSA {
    this.parsedData = data

    return this
}

// 设置编码方式
func (this ECDSA) WithEncoding(encoding EncodingType) ECDSA {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this ECDSA) WithEncodingASN1() ECDSA {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this ECDSA) WithEncodingBytes() ECDSA {
    return this.WithEncoding(EncodingBytes)
}

// 设置验证结果
func (this ECDSA) WithVerify(data bool) ECDSA {
    this.verify = data

    return this
}

// 设置错误
func (this ECDSA) WithErrors(errs []error) ECDSA {
    this.Errors = errs

    return this
}
