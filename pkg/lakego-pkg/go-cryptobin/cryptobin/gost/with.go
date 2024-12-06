package gost

import (
    "github.com/deatil/go-cryptobin/tool/hash"
    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// 设置 PrivateKey
func (this Gost) WithPrivateKey(data *gost.PrivateKey) Gost {
    this.privateKey = data

    return this
}

// 设置 PublicKey
func (this Gost) WithPublicKey(data *gost.PublicKey) Gost {
    this.publicKey = data

    return this
}

// 设置 data
func (this Gost) WithData(data []byte) Gost {
    this.data = data

    return this
}

// 设置 parsedData
func (this Gost) WithParsedData(data []byte) Gost {
    this.parsedData = data

    return this
}

// 设置曲线类型
// set gost curve
func (this Gost) WithCurve(curve *gost.Curve) Gost {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选参数:
// IdGostR34102001TestParamSet
// IdGostR34102001CryptoProAParamSet
// IdGostR34102001CryptoProBParamSet
// IdGostR34102001CryptoProCParamSet
// IdGostR34102001CryptoProXchAParamSet
// IdGostR34102001CryptoProXchBParamSet
// Idtc26gost34102012256paramSetA
// Idtc26gost34102012256paramSetB
// Idtc26gost34102012256paramSetC
// Idtc26gost34102012256paramSetD
// Idtc26gost34102012512paramSetTest
// Idtc26gost34102012512paramSetA
// Idtc26gost34102012512paramSetB
// Idtc26gost34102012512paramSetC
func (this Gost) SetCurve(curve string) Gost {
    switch curve {
        case "IdGostR34102001TestParamSet":
            this.curve = gost.CurveIdGostR34102001TestParamSet()
        case "IdGostR34102001CryptoProAParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProAParamSet()
        case "IdGostR34102001CryptoProBParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProBParamSet()
        case "IdGostR34102001CryptoProCParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProCParamSet()

        case "IdGostR34102001CryptoProXchAParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProXchAParamSet()
        case "IdGostR34102001CryptoProXchBParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProXchBParamSet()

        case "Idtc26gost34102012256paramSetA":
            this.curve = gost.CurveIdtc26gost34102012256paramSetA()
        case "Idtc26gost34102012256paramSetB":
            this.curve = gost.CurveIdtc26gost34102012256paramSetB()
        case "Idtc26gost34102012256paramSetC":
            this.curve = gost.CurveIdtc26gost34102012256paramSetC()
        case "Idtc26gost34102012256paramSetD":
            this.curve = gost.CurveIdtc26gost34102012256paramSetD()

        case "Idtc26gost34102012512paramSetTest":
            this.curve = gost.CurveIdtc26gost34102012512paramSetTest()
        case "Idtc26gost34102012512paramSetA":
            this.curve = gost.CurveIdtc26gost34102012512paramSetA()
        case "Idtc26gost34102012512paramSetB":
            this.curve = gost.CurveIdtc26gost34102012512paramSetB()
        case "Idtc26gost34102012512paramSetC":
            this.curve = gost.CurveIdtc26gost34102012512paramSetC()
    }

    return this
}

// 设置 hash 类型
func (this Gost) WithSignHash(data HashFunc) Gost {
    this.signHash = data

    return this
}

// 设置 hash 类型
// 可用参数可查看 Hash 结构体数据
func (this Gost) SetSignHash(data string) Gost {
    hash, err := hash.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
}

// 设置编码方式
func (this Gost) WithEncoding(encoding EncodingType) Gost {
    this.encoding = encoding

    return this
}

// 设置 ASN1 编码方式
func (this Gost) WithEncodingASN1() Gost {
    return this.WithEncoding(EncodingASN1)
}

// 设置明文编码方式
func (this Gost) WithEncodingBytes() Gost {
    return this.WithEncoding(EncodingBytes)
}

// 设置 verify
func (this Gost) WithVerify(data bool) Gost {
    this.verify = data

    return this
}

// 设置 secretData
func (this Gost) WithSecretData(data []byte) Gost {
    this.secretData = data

    return this
}

// 设置错误
func (this Gost) WithErrors(errs []error) Gost {
    this.Errors = errs

    return this
}
