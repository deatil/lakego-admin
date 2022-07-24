package cryptobin

import (
    "errors"
    "crypto/x509"
    "encoding/pem"
)

type (
    // 配置别名
    X509VerifyOptions = x509.VerifyOptions
)

// 验证
func (this CA) verify(rootPEM string, certPEM string, opts x509.VerifyOptions) (bool, error) {
    roots := x509.NewCertPool()
    ok := roots.AppendCertsFromPEM([]byte(rootPEM))
    if !ok {
        return false, errors.New("failed to parse root certificate")
    }

    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        return false, errors.New("failed to parse certificate PEM")
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return false, errors.New("failed to parse certificate: " + err.Error())
    }

    // 重设
    opts.Roots = roots

    if _, err := cert.Verify(opts); err != nil {
        return false, errors.New("failed to verify certificate: " + err.Error())
    }

    return true, nil
}
