package cryptobin

import (
    "crypto/x509"
)

// 获取 cert
func (this CA) GetCert() any {
    return this.cert
}

// 获取 certRequest
func (this CA) GetCertRequest() any {
    return this.certRequest
}

// 获取 PrivateKey
func (this CA) GetPrivateKey() any {
    return this.privateKey
}

// 获取 publicKey
func (this CA) GetPublicKey() any {
    return this.publicKey
}

// 获取 keyData
func (this CA) GetKeyData() []byte {
    return this.keyData
}

// 获取错误
func (this CA) GetError() error {
    return this.Error
}

// =========================

// 获取签名 alg
func (this CA) GetSignatureAlgorithm(name string) x509.SignatureAlgorithm {
    data := map[string]x509.SignatureAlgorithm {
        // "MD2WithRSA":    x509.MD2WithRSA,  // Unsupported.
        "MD5WithRSA":       x509.MD5WithRSA,  // Only supported for signing, not verification.
        "SHA1WithRSA":      x509.SHA1WithRSA, // Only supported for signing, not verification.
        "SHA256WithRSA":    x509.SHA256WithRSA,
        "SHA384WithRSA":    x509.SHA384WithRSA,
        "SHA512WithRSA":    x509.SHA512WithRSA,
        // "DSAWithSHA1":   x509.DSAWithSHA1,   // Unsupported.
        // "DSAWithSHA256": x509.DSAWithSHA256, // Unsupported.
        "ECDSAWithSHA1":    x509.ECDSAWithSHA1, // Only supported for signing, not verification.
        "ECDSAWithSHA256":  x509.ECDSAWithSHA256,
        "ECDSAWithSHA384":  x509.ECDSAWithSHA384,
        "ECDSAWithSHA512":  x509.ECDSAWithSHA512,
        "SHA256WithRSAPSS": x509.SHA256WithRSAPSS,
        "SHA384WithRSAPSS": x509.SHA384WithRSAPSS,
        "SHA512WithRSAPSS": x509.SHA512WithRSAPSS,
        "PureEd25519":      x509.PureEd25519,
    }

    if alg, ok := data[name]; ok {
        return alg
    }

    return data["SHA256WithRSA"]
}
