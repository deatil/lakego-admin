package ca

import (
    "crypto/x509"

    sm2X509 "github.com/tjfoc/gmsm/x509"

    cryptobin_tool "github.com/deatil/go-cryptobin/tool"
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
func (this CA) GetErrors() []error {
    return this.Errors
}

// 获取错误
func (this CA) Error() *cryptobin_tool.Errors {
    return cryptobin_tool.NewError(this.Errors...)
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

// 获取 SM2 签名 alg
func (this CA) GetSM2SignatureAlgorithm(name string) sm2X509.SignatureAlgorithm {
    data := map[string]sm2X509.SignatureAlgorithm {
        "MD2WithRSA":       sm2X509.MD2WithRSA,
        "MD5WithRSA":       sm2X509.MD5WithRSA,
        // "MD2WithRSA":    sm2X509.MD2WithRSA,  // Unsupported.
        "SHA1WithRSA":      sm2X509.SHA1WithRSA,
        "SHA256WithRSA":    sm2X509.SHA256WithRSA,
        "SHA384WithRSA":    sm2X509.SHA384WithRSA,
        "SHA512WithRSA":    sm2X509.SHA512WithRSA,
        // "DSAWithSHA1":   x509.DSAWithSHA1,   // Unsupported.
        // "DSAWithSHA256": x509.DSAWithSHA256, // Unsupported.
        "ECDSAWithSHA1":    sm2X509.ECDSAWithSHA1,
        "ECDSAWithSHA256":  sm2X509.ECDSAWithSHA256,
        "ECDSAWithSHA384":  sm2X509.ECDSAWithSHA384,
        "ECDSAWithSHA512":  sm2X509.ECDSAWithSHA512,
        "SHA256WithRSAPSS": sm2X509.SHA256WithRSAPSS,
        "SHA384WithRSAPSS": sm2X509.SHA384WithRSAPSS,
        "SHA512WithRSAPSS": sm2X509.SHA512WithRSAPSS,
        "SM2WithSM3":       sm2X509.SM2WithSM3,
        "SM2WithSHA1":      sm2X509.SM2WithSHA1,
        "SM2WithSHA256":    sm2X509.SM2WithSHA256,
    }

    if alg, ok := data[name]; ok {
        return alg
    }

    return data["SM2WithSHA1"]
}
