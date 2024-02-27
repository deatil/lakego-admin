package ca

import (
    "crypto/x509"
    "crypto/x509/pkix"

    cryptobin_x509 "github.com/deatil/go-cryptobin/x509"
)

// pkix
type (
    // Subject 数据
    CAPkixName = pkix.Name

    // Extension
    CAPkixExtension = pkix.Extension

    // CertificateList
    CAPkixCertificateList = pkix.CertificateList

    // RevokedCertificate
    CAPkixRevokedCertificate = pkix.RevokedCertificate

    // TBSCertificateList
    CAPkixTBSCertificateList = pkix.TBSCertificateList

    // RDNSequence
    CAPkixRDNSequence = pkix.RDNSequence

    // AttributeTypeAndValue 数据
    CAPkixAttributeTypeAndValue = pkix.AttributeTypeAndValue

    // AlgorithmIdentifier
    CAPkixAlgorithmIdentifier = pkix.AlgorithmIdentifier

    // AttributeTypeAndValueSET
    CAPkixAttributeTypeAndValueSET = pkix.AttributeTypeAndValueSET
)

// x905
type (
    // 证书
    CACertificate = x509.Certificate

    // 证书请求
    CACertificateRequest = x509.CertificateRequest

    // 配置别名
    CAVerifyOptions = x509.VerifyOptions

    // KeyUsage
    CAKeyUsage = x509.KeyUsage

    // ExtKeyUsage
    CAExtKeyUsage = x509.ExtKeyUsage

    // SignatureAlgorithm
    CASignatureAlgorithm = x509.SignatureAlgorithm

    // PublicKeyAlgorithm
    CAPublicKeyAlgorithm = x509.PublicKeyAlgorithm
)

// sm2-x905
type (
    // SM2 证书
    SM2CACertificate = cryptobin_x509.Certificate

    // SM2 证书请求
    SM2CACertificateRequest = cryptobin_x509.CertificateRequest

    // 配置别名
    SM2CAVerifyOptions = cryptobin_x509.VerifyOptions

    // KeyUsage
    SM2CAKeyUsage = cryptobin_x509.KeyUsage

    // ExtKeyUsage
    SM2CAExtKeyUsage = cryptobin_x509.ExtKeyUsage

    // SignatureAlgorithm
    SM2CASignatureAlgorithm = cryptobin_x509.SignatureAlgorithm

    // PublicKeyAlgorithm
    SM2CAPublicKeyAlgorithm = cryptobin_x509.PublicKeyAlgorithm
)
