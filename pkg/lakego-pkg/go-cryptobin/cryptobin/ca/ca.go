package ca

import (
    "strconv"
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"
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
)

// Options
type Options struct {
    // public key type
    PublicKeyType PublicKeyType

    // DSA ParameterSizes
    ParameterSizes dsa.ParameterSizes

    // ecc curve
    Curve elliptic.Curve

    // generates RSA private key bit size
    Bits int
}

/**
 * CA
 *
 * @create 2022-7-22
 * @author deatil
 */
type CA struct {
    // 证书数据
    // 可用 [*x509.Certificate | *sm2X509.Certificate]
    cert any

    // 证书请求
    // 可用 [*x509.CertificateRequest | *sm2X509.CertificateRequest]
    certRequest any

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
            Bits:           2048,
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
