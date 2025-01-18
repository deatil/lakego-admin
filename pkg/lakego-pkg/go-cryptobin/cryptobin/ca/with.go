package ca

import (
    "crypto"
    "crypto/dsa"
    "crypto/elliptic"
)

// 设置 cert
// 可用 [*x509.Certificate | *sm2X509.Certificate]
func (this CA) WithCert(cert any) CA {
    this.cert = cert

    return this
}

// 设置 certRequest
// 可用 [*x509.CertificateRequest | *sm2X509.CertificateRequest]
func (this CA) WithCertRequest(cert any) CA {
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

// public key type
// params:
// [ RSA | DSA | ECDSA | EdDSA | SM2 ]
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
    }

    return this
}

// set Generate public key type
// params:
// [ RSA | DSA | ECDSA | EdDSA | SM2 ]
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

// RSA private key bit size
func (this CA) WithBits(bits int) CA {
    this.options.Bits = bits

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
