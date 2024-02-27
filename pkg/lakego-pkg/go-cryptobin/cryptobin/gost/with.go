package gost

import (
    "github.com/deatil/go-cryptobin/gost"
    "github.com/deatil/go-cryptobin/tool"
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
func (this Gost) WithCurve(curve *gost.Curve) Gost {
    this.curve = curve

    return this
}

// 设置曲线类型
// 可选参数:
// CurveIdGostR34102001TestParamSet
// CurveIdGostR34102001CryptoProAParamSet
// CurveIdGostR34102001CryptoProBParamSet
// CurveIdGostR34102001CryptoProCParamSet
// CurveIdGostR34102001CryptoProXchAParamSet
// CurveIdGostR34102001CryptoProXchBParamSet
// CurveIdtc26gost34102012256paramSetA
// CurveIdtc26gost34102012256paramSetB
// CurveIdtc26gost34102012256paramSetC
// CurveIdtc26gost34102012256paramSetD
// CurveIdtc26gost34102012512paramSetTest
// CurveIdtc26gost34102012512paramSetA
// CurveIdtc26gost34102012512paramSetB
// CurveIdtc26gost34102012512paramSetC
func (this Gost) SetCurve(curve string) Gost {
    switch curve {
        case "CurveIdGostR34102001TestParamSet":
            this.curve = gost.CurveIdGostR34102001TestParamSet()
        case "CurveIdGostR34102001CryptoProAParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProAParamSet()
        case "CurveIdGostR34102001CryptoProBParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProBParamSet()
        case "CurveIdGostR34102001CryptoProCParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProCParamSet()

        case "CurveIdGostR34102001CryptoProXchAParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProXchAParamSet()
        case "CurveIdGostR34102001CryptoProXchBParamSet":
            this.curve = gost.CurveIdGostR34102001CryptoProXchBParamSet()

        case "CurveIdtc26gost34102012256paramSetA":
            this.curve = gost.CurveIdtc26gost34102012256paramSetA()
        case "CurveIdtc26gost34102012256paramSetB":
            this.curve = gost.CurveIdtc26gost34102012256paramSetB()
        case "CurveIdtc26gost34102012256paramSetC":
            this.curve = gost.CurveIdtc26gost34102012256paramSetC()
        case "CurveIdtc26gost34102012256paramSetD":
            this.curve = gost.CurveIdtc26gost34102012256paramSetD()

        case "CurveIdtc26gost34102012512paramSetTest":
            this.curve = gost.CurveIdtc26gost34102012512paramSetTest()
        case "CurveIdtc26gost34102012512paramSetA":
            this.curve = gost.CurveIdtc26gost34102012512paramSetA()
        case "CurveIdtc26gost34102012512paramSetB":
            this.curve = gost.CurveIdtc26gost34102012512paramSetB()
        case "CurveIdtc26gost34102012512paramSetC":
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
    hash, err := tool.GetHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = hash

    return this
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
