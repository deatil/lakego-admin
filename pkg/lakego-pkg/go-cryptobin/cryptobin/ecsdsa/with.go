package ecsdsa

import (
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/hash"
    "github.com/deatil/go-cryptobin/pubkey/ecsdsa"
    "github.com/deatil/go-cryptobin/elliptic/brainpool"
)

// 设置 PrivateKey
func (this ECSDSA) WithPrivateKey(data *ecsdsa.PrivateKey) ECSDSA {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this ECSDSA) WithPublicKey(data *ecsdsa.PublicKey) ECSDSA {
    this.publicKey = data

    return this
}

// 设置曲线类型
func (this ECSDSA) WithCurve(curve elliptic.Curve) ECSDSA {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选参数:
// [ P521 | P384 | P256 | P224 |
// BrainpoolP256r1 | BrainpoolP256t1
// BrainpoolP320r1 | BrainpoolP320t1
// BrainpoolP384r1 | BrainpoolP384t1
// BrainpoolP512r1 | BrainpoolP512t1 ]
func (this ECSDSA) SetCurve(curve string) ECSDSA {
    switch curve {
        case "P224":
            this.curve = elliptic.P224()
        case "P256":
            this.curve = elliptic.P256()
        case "P384":
            this.curve = elliptic.P384()
        case "P521":
            this.curve = elliptic.P521()

        case "BrainpoolP256r1":
            this.curve = brainpool.P256r1()
        case "BrainpoolP256t1":
            this.curve = brainpool.P256t1()
        case "BrainpoolP320r1":
            this.curve = brainpool.P320r1()
        case "BrainpoolP320t1":
            this.curve = brainpool.P320t1()
        case "BrainpoolP384r1":
            this.curve = brainpool.P384r1()
        case "BrainpoolP384t1":
            this.curve = brainpool.P384t1()
        case "BrainpoolP512r1":
            this.curve = brainpool.P512r1()
        case "BrainpoolP512t1":
            this.curve = brainpool.P512t1()
    }

    return this
}

// 设置 hash 类型
func (this ECSDSA) WithSignHash(hash HashFunc) ECSDSA {
    this.signHash = hash

    return this
}

// 设置 hash 类型
func (this ECSDSA) SetSignHash(name string) ECSDSA {
    h, err := hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = h

    return this
}

// 设置 data
func (this ECSDSA) WithData(data []byte) ECSDSA {
    this.data = data

    return this
}

// 设置 parsedData
func (this ECSDSA) WithParsedData(data []byte) ECSDSA {
    this.parsedData = data

    return this
}

// 设置编码方式
func (this ECSDSA) WithEncoding(encoding EncodingType) ECSDSA {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this ECSDSA) WithEncodingASN1() ECSDSA {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this ECSDSA) WithEncodingBytes() ECSDSA {
    return this.WithEncoding(EncodingBytes)
}

// 设置验证结果
func (this ECSDSA) WithVerify(data bool) ECSDSA {
    this.verify = data

    return this
}

// 设置错误
func (this ECSDSA) WithErrors(errs []error) ECSDSA {
    this.Errors = errs

    return this
}
