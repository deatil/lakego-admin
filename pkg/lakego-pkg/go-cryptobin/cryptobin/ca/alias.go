package ca

import (
    "crypto/x509"
    "crypto/x509/pkix"

    sm2X509 "github.com/tjfoc/gmsm/x509"
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
    CASM2Certificate = sm2X509.Certificate

    // SM2 证书请求
    CASM2CertificateRequest = sm2X509.CertificateRequest

    // 配置别名
    CASM2VerifyOptions = sm2X509.VerifyOptions

    // KeyUsage
    CASM2KeyUsage = sm2X509.KeyUsage

    // ExtKeyUsage
    CASM2ExtKeyUsage = sm2X509.ExtKeyUsage

    // SignatureAlgorithm
    CASM2SignatureAlgorithm = sm2X509.SignatureAlgorithm

    // PublicKeyAlgorithm
    CASM2PublicKeyAlgorithm = sm2X509.PublicKeyAlgorithm
)
