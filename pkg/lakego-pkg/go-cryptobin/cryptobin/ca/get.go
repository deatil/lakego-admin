package ca

import (
    "crypto"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/pubkey/gost"
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
)

// 获取 cert
func (this CA) GetCert() *x509.Certificate {
    return this.cert
}

// 获取 certRequest
func (this CA) GetCertRequest() *x509.CertificateRequest {
    return this.certRequest
}

// 获取 PrivateKey
func (this CA) GetPrivateKey() crypto.PrivateKey {
    return this.privateKey
}

// get PrivateKey Type
func (this CA) GetPrivateKeyType() PublicKeyType {
    switch this.privateKey.(type) {
        case *rsa.PrivateKey:
            return KeyTypeRSA
        case *dsa.PrivateKey:
            return KeyTypeDSA
        case *ecdsa.PrivateKey:
            return KeyTypeECDSA
        case ed25519.PrivateKey:
            return KeyTypeEdDSA
        case *sm2.PrivateKey:
            return KeyTypeSM2
        case *gost.PrivateKey:
            return KeyTypeGost
        case *elgamal.PrivateKey:
            return KeyTypeElGamal
    }

    return KeyTypeUnknown
}

// 获取 publicKey
func (this CA) GetPublicKey() crypto.PublicKey {
    return this.publicKey
}

// get PublicKey Type
func (this CA) GetPublicKeyType() PublicKeyType {
    switch this.publicKey.(type) {
        case *rsa.PublicKey:
            return KeyTypeRSA
        case *dsa.PublicKey:
            return KeyTypeDSA
        case *ecdsa.PublicKey:
            return KeyTypeECDSA
        case ed25519.PublicKey:
            return KeyTypeEdDSA
        case *sm2.PublicKey:
            return KeyTypeSM2
        case *gost.PublicKey:
            return KeyTypeGost
        case *elgamal.PublicKey:
            return KeyTypeElGamal
    }

    return KeyTypeUnknown
}

// get Options
func (this CA) GetOptions() Options {
    return this.options
}

// get DSA ParameterSizes
func (this CA) GetParameterSizes() dsa.ParameterSizes {
    return this.options.ParameterSizes
}

// get Options Curve
func (this CA) GetCurve() elliptic.Curve {
    return this.options.Curve
}

// 获取 Curve
func (this CA) GetGostCurve() *gost.Curve {
    return this.options.GostCurve
}

// get Options Bits
func (this CA) GetBits() int {
    return this.options.Bits
}

// get Options Bitsize
func (this CA) GetBitsize() int {
    return this.options.Bitsize
}

// get Options Probability
func (this CA) GetProbability() int {
    return this.options.Probability
}

// 获取 keyData
func (this CA) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this CA) GetErrors() []error {
    return this.Errors
}
