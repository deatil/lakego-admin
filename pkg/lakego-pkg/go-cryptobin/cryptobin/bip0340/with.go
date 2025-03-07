package bip0340

import (
    "encoding/asn1"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/hash"
    "github.com/deatil/go-cryptobin/pubkey/bip0340"
    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

// Add Named Curve
func (this BIP0340) AddNamedCurve(curve elliptic.Curve, oid asn1.ObjectIdentifier) BIP0340 {
    bip0340.AddNamedCurve(curve, oid)
    return this
}

// Add Named Curve
func AddNamedCurve(curve elliptic.Curve, oid asn1.ObjectIdentifier) BIP0340 {
    return defaultBIP0340.AddNamedCurve(curve, oid)
}

// 设置 PrivateKey
func (this BIP0340) WithPrivateKey(data *bip0340.PrivateKey) BIP0340 {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this BIP0340) WithPublicKey(data *bip0340.PublicKey) BIP0340 {
    this.publicKey = data

    return this
}

// 设置曲线类型
func (this BIP0340) WithCurve(curve elliptic.Curve) BIP0340 {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选参数:
// [ P521 | P384 | P256 | P224 | S256 ]
func (this BIP0340) SetCurve(curve string) BIP0340 {
    switch curve {
        case "P224":
            this.curve = elliptic.P224()
        case "P256":
            this.curve = elliptic.P256()
        case "P384":
            this.curve = elliptic.P384()
        case "P521":
            this.curve = elliptic.P521()
        case "S256":
            this.curve = secp256k1.S256()
    }

    return this
}

// 设置 hash 类型
func (this BIP0340) WithSignHash(hash HashFunc) BIP0340 {
    this.signHash = hash

    return this
}

// 设置 hash 类型
func (this BIP0340) SetSignHash(name string) BIP0340 {
    h, err := hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = h

    return this
}

// 设置 data
func (this BIP0340) WithData(data []byte) BIP0340 {
    this.data = data

    return this
}

// 设置 parsedData
func (this BIP0340) WithParsedData(data []byte) BIP0340 {
    this.parsedData = data

    return this
}

// 设置编码方式
func (this BIP0340) WithEncoding(encoding EncodingType) BIP0340 {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this BIP0340) WithEncodingASN1() BIP0340 {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this BIP0340) WithEncodingBytes() BIP0340 {
    return this.WithEncoding(EncodingBytes)
}

// 设置验证结果
func (this BIP0340) WithVerify(data bool) BIP0340 {
    this.verify = data

    return this
}

// 设置错误
func (this BIP0340) WithErrors(errs []error) BIP0340 {
    this.Errors = errs

    return this
}
