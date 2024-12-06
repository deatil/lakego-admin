package ecgdsa

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/hash"
    "github.com/deatil/go-cryptobin/pubkey/ecgdsa"
)

// 设置 PrivateKey
func (this ECGDSA) WithPrivateKey(data *ecgdsa.PrivateKey) ECGDSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ECGDSA) WithPublicKey(data *ecgdsa.PublicKey) ECGDSA {
    this.publicKey = data

    return this
}

// 设置曲线类型
func (this ECGDSA) WithCurve(curve elliptic.Curve) ECGDSA {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选参数 [P521 | P384 | P256 | P224]
func (this ECGDSA) SetCurve(curve string) ECGDSA {
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
func (this ECGDSA) WithSignHash(hash HashFunc) ECGDSA {
    this.signHash = hash

    return this
}

// 设置 hash 类型
func (this ECGDSA) SetSignHash(name string) ECGDSA {
    h, err := hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = h

    return this
}

// 设置 data
func (this ECGDSA) WithData(data []byte) ECGDSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this ECGDSA) WithParsedData(data []byte) ECGDSA {
    this.parsedData = data

    return this
}

// 设置编码方式
func (this ECGDSA) WithEncoding(encoding EncodingType) ECGDSA {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this ECGDSA) WithEncodingASN1() ECGDSA {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this ECGDSA) WithEncodingBytes() ECGDSA {
    return this.WithEncoding(EncodingBytes)
}

// 设置验证结果
func (this ECGDSA) WithVerify(data bool) ECGDSA {
    this.verify = data

    return this
}

// 设置错误
func (this ECGDSA) WithErrors(errs []error) ECGDSA {
    this.Errors = errs

    return this
}
