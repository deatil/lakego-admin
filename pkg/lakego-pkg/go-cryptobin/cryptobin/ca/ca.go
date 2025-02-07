package ca

import (
    "strconv"
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// public key type
type PublicKeyType uint

func (typ PublicKeyType) String() string {
    switch typ {
        case KeyTypeUnknown:
            return "Unknown"
        case KeyTypeRSA:
            return "RSA"
        case KeyTypeDSA:
            return "DSA"
        case KeyTypeECDSA:
            return "ECDSA"
        case KeyTypeEdDSA:
            return "EdDSA"
        case KeyTypeSM2:
            return "SM2"
        case KeyTypeGost:
            return "Gost"
        case KeyTypeElGamal:
            return "ElGamal"
        default:
            return "unknown KeyType value " + strconv.Itoa(int(typ))
    }
}

const (
    KeyTypeUnknown PublicKeyType = iota
    KeyTypeRSA
    KeyTypeDSA
    KeyTypeECDSA
    KeyTypeEdDSA
    KeyTypeSM2
    KeyTypeGost
    KeyTypeElGamal
)

// Options
type Options struct {
    // public key type
    PublicKeyType PublicKeyType

    // generates DSA ParameterSizes
    ParameterSizes dsa.ParameterSizes

    // generates ECC curve
    Curve elliptic.Curve

    // generates Gost curve
    GostCurve *gost.Curve

    // generates RSA private key bit size
    Bits int

    // generates ElGamal private key bit size and probability
    Bitsize, Probability int
}

/**
 * CA
 *
 * @create 2022-7-22
 * @author deatil
 */
type CA struct {
    // 证书数据
    cert *x509.Certificate

    // 请求证书
    certRequest *x509.CertificateRequest

    // 私钥
    // 可用 [*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey | *sm2.PrivateKey]
    privateKey crypto.PrivateKey

    // 公钥
    // 可用 [*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey | *sm2.PublicKey]
    publicKey crypto.PublicKey

    // options
    options Options

    // [私钥/公钥/cert]数据
    keyData []byte

    // 错误
    Errors []error
}

// 构造函数
func NewCA() CA {
    return CA{
        options: Options{
            PublicKeyType:  KeyTypeRSA,
            ParameterSizes: dsa.L1024N160,
            Curve:          elliptic.P256(),
            GostCurve:      gost.CurveDefault(),
            Bits:           2048,
            Bitsize:        256,
            Probability:    64,
        },
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() CA {
    return NewCA()
}

var (
    // 默认
    defaultCA = NewCA()
)
