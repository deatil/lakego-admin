package ca

import (
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// 设置 cert
func (this CA) WithCert(cert *x509.Certificate) CA {
    this.cert = cert

    return this
}

// 设置 certRequest
func (this CA) WithCertRequest(cert *x509.CertificateRequest) CA {
    this.certRequest = cert

    return this
}

// 设置 PrivateKey
func (this CA) WithPrivateKey(key crypto.PrivateKey) CA {
    this.privateKey = key

    return this
}

// 设置 publicKey
func (this CA) WithPublicKey(key crypto.PublicKey) CA {
    this.publicKey = key

    return this
}

// With options
func (this CA) WithOptions(options Options) CA {
    this.options = options

    return this
}

// public key type
func (this CA) WithPublicKeyType(keyType PublicKeyType) CA {
    this.options.PublicKeyType = keyType

    return this
}

// set public key type
// params:
// [ RSA | DSA | ECDSA | EdDSA | SM2 | Gost | ElGamal ]
func (this CA) SetPublicKeyType(keyType string) CA {
    switch keyType {
        case "RSA":
            this.options.PublicKeyType = KeyTypeRSA
        case "DSA":
            this.options.PublicKeyType = KeyTypeDSA
        case "ECDSA":
            this.options.PublicKeyType = KeyTypeECDSA
        case "EdDSA":
            this.options.PublicKeyType = KeyTypeEdDSA
        case "SM2":
            this.options.PublicKeyType = KeyTypeSM2
        case "Gost":
            this.options.PublicKeyType = KeyTypeGost
        case "ElGamal":
            this.options.PublicKeyType = KeyTypeElGamal
    }

    return this
}

// set Generate public key type
// params:
// [ RSA | DSA | ECDSA | EdDSA | SM2 | Gost | ElGamal ]
func (this CA) SetGenerateType(typ string) CA {
    return this.SetPublicKeyType(typ)
}

// With DSA ParameterSizes
func (this CA) WithParameterSizes(sizes dsa.ParameterSizes) CA {
    this.options.ParameterSizes = sizes

    return this
}

// With DSA ParameterSizes
// params:
// [ L1024N160 | L2048N224 | L2048N256 | L3072N256 ]
func (this CA) SetParameterSizes(ln string) CA {
    switch ln {
        case "L1024N160":
            this.options.ParameterSizes = dsa.L1024N160
        case "L2048N224":
            this.options.ParameterSizes = dsa.L2048N224
        case "L2048N256":
            this.options.ParameterSizes = dsa.L2048N256
        case "L3072N256":
            this.options.ParameterSizes = dsa.L3072N256
    }

    return this
}

// With Curve type
func (this CA) WithCurve(curve elliptic.Curve) CA {
    this.options.Curve = curve

    return this
}

// set Curve type
// params: [ P521 | P384 | P256 | P224 ]
func (this CA) SetCurve(curve string) CA {
    switch curve {
        case "P224":
            this.options.Curve = elliptic.P224()
        case "P256":
            this.options.Curve = elliptic.P256()
        case "P384":
            this.options.Curve = elliptic.P384()
        case "P521":
            this.options.Curve = elliptic.P521()
    }

    return this
}

// 设置曲线类型
// set gost curve
func (this CA) WithGostCurve(curve *gost.Curve) CA {
    this.options.GostCurve = curve

    return this
}

// 设置曲线类型
// set gost curve
// 可选参数 / params:
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
func (this CA) SetGostCurve(curve string) CA {
    switch curve {
        case "IdGostR34102001TestParamSet":
            this.options.GostCurve = gost.CurveIdGostR34102001TestParamSet()
        case "IdGostR34102001CryptoProAParamSet":
            this.options.GostCurve = gost.CurveIdGostR34102001CryptoProAParamSet()
        case "IdGostR34102001CryptoProBParamSet":
            this.options.GostCurve = gost.CurveIdGostR34102001CryptoProBParamSet()
        case "IdGostR34102001CryptoProCParamSet":
            this.options.GostCurve = gost.CurveIdGostR34102001CryptoProCParamSet()

        case "IdGostR34102001CryptoProXchAParamSet":
            this.options.GostCurve = gost.CurveIdGostR34102001CryptoProXchAParamSet()
        case "IdGostR34102001CryptoProXchBParamSet":
            this.options.GostCurve = gost.CurveIdGostR34102001CryptoProXchBParamSet()

        case "Idtc26gost34102012256paramSetA":
            this.options.GostCurve = gost.CurveIdtc26gost34102012256paramSetA()
        case "Idtc26gost34102012256paramSetB":
            this.options.GostCurve = gost.CurveIdtc26gost34102012256paramSetB()
        case "Idtc26gost34102012256paramSetC":
            this.options.GostCurve = gost.CurveIdtc26gost34102012256paramSetC()
        case "Idtc26gost34102012256paramSetD":
            this.options.GostCurve = gost.CurveIdtc26gost34102012256paramSetD()

        case "Idtc26gost34102012512paramSetTest":
            this.options.GostCurve = gost.CurveIdtc26gost34102012512paramSetTest()
        case "Idtc26gost34102012512paramSetA":
            this.options.GostCurve = gost.CurveIdtc26gost34102012512paramSetA()
        case "Idtc26gost34102012512paramSetB":
            this.options.GostCurve = gost.CurveIdtc26gost34102012512paramSetB()
        case "Idtc26gost34102012512paramSetC":
            this.options.GostCurve = gost.CurveIdtc26gost34102012512paramSetC()
    }

    return this
}

// RSA private key bit size
func (this CA) WithBits(bits int) CA {
    this.options.Bits = bits

    return this
}

// ElGamal private key bit size
func (this CA) WithBitsize(bits int) CA {
    this.options.Bitsize = bits

    return this
}

// ElGamal private key probability size
func (this CA) WithProbability(probability int) CA {
    this.options.Probability = probability

    return this
}

// 设置 keyData
func (this CA) WithKeyData(data []byte) CA {
    this.keyData = data

    return this
}

// 设置错误
func (this CA) WithErrors(errs []error) CA {
    this.Errors = errs

    return this
}
