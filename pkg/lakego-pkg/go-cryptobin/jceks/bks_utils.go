package jceks

import (
    "crypto/x509"
)

// 解析证书链
func parseCertChain(certChain [][]byte) (certs []*x509.Certificate, err error) {
    for _, cert := range certChain {
        var parsedCert *x509.Certificate
        parsedCert, err = x509.ParseCertificate(cert)
        if err != nil {
            return
        }

        certs = append(certs, parsedCert)
    }

    return
}

