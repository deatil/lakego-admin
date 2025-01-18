package ssh

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

    // Cipher Name
    CipherName string

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

    // PrivateKey and PublicKey data
    keyData []byte

    // input data
    data []byte

    // parsed Data
    parsedData []byte

    // verify data
    verify bool

    // error list
    Errors []error
}

// NewSSH return a new SSH
func NewSSH() SSH {
    return SSH{
        options: Options{
            PublicKeyType:  KeyTypeRSA,
            ParameterSizes: dsa.L1024N160,
            Curve:          elliptic.P256(),
            Bits:           2048,
        },
        verify: false,
        Errors: make([]error, 0),
    }
}

// New return a new SSH
func New() SSH {
    return NewSSH()
}

var (
    // default New SSH
    defaultSSH = NewSSH()
)
