package cryptobin

import (
    "crypto/x509"

    sm2X509 "github.com/tjfoc/gmsm/x509"
)

type (
    // 证书
    CACertificate = x509.Certificate

    // 证书请求
    CACertificateRequest = x509.CertificateRequest

    // SM2 证书
    CASM2Certificate = sm2X509.Certificate

    // SM2 证书请求
    CASM2CertificateRequest = sm2X509.CertificateRequest
)

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
    privateKey any

    // 公钥
    publicKey any

    // [私钥/公钥/cert]数据
    keyData []byte

    // 错误
    Error error
}

// 更新数据
func (this CA) Update(fn func(CA) CA) CA {
    return fn(this)
}
