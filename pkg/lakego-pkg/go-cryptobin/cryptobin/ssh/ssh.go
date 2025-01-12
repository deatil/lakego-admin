package ecgdsa

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
    KeyTypeRSA PublicKeyType = 1 + iota
    KeyTypeDSA
    KeyTypeECDSA
    KeyTypeEdDSA
    KeyTypeSM2
)

// Options
type Options struct {
    // public key type
    PublicKeyType PublicKeyType

    // comment data
    Comment string

    // DSA ParameterSizes
    ParameterSizes dsa.ParameterSizes

    // ecc curve
    Curve elliptic.Curve

    // generates RSA private key bit size
    Bits int
}

/**
 * SSH
 *
 * @create 2025-1-12
 * @author deatil
 */
type SSH struct {
    // PrivateKey
    privateKey crypto.PrivateKey

    // PublicKey
    publicKey crypto.PublicKey

    // options
    options Options

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    parsedData []byte

    // 验证结果
    verify bool

    // 错误
    Errors []error
}

// 构造函数
func NewSSH() SSH {
    return SSH{
        options: Options{
            PublicKeyType:  KeyTypeRSA,
            ParameterSizes: dsa.L1024N160,
            Curve:          elliptic.P256(),
            Bits:           2048,
        },
        verify:   false,
        Errors:   make([]error, 0),
    }
}

// 构造函数
func New() SSH {
    return NewSSH()
}

var (
    // 默认
    defaultSSH = NewSSH()
)
