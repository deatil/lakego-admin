package cryptobin

import (
    "crypto/x509"
    "crypto/x509/pkix"

    sm2X509 "github.com/tjfoc/gmsm/x509"
)

type (
    // Subject 数据
    CAPkixName = pkix.Name

    // 证书
    CACertificate = x509.Certificate

    // 证书请求
    CACertificateRequest = x509.CertificateRequest

    // SM2 证书
    CASM2Certificate = sm2X509.Certificate

    // SM2 证书请求
    CASM2CertificateRequest = sm2X509.CertificateRequest
)
