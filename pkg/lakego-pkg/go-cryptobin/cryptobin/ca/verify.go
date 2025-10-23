package ca

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/x509"
)

// 验证
func (this CA) Verify(rootPEM string, certPEM string, opts x509.VerifyOptions) (bool, error) {
    roots := x509.NewCertPool()

    ok := roots.AppendCertsFromPEM([]byte(rootPEM))
    if !ok {
        return false, errors.New("go-cryptobin/ca: failed to parse root certificate")
    }

    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        return false, errors.New("go-cryptobin/ca: failed to parse certificate PEM")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return false, errors.New("go-cryptobin/ca: failed to parse certificate: " + err.Error())
    }

    // 重设
    opts.Roots = roots

    if _, err := cert.Verify(opts); err != nil {
        return false, errors.New("go-cryptobin/ca: failed to verify certificate: " + err.Error())
    }

    return true, nil
}
