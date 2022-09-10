package ca

import (
    "errors"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"

    "github.com/tjfoc/gmsm/sm2"
    sm2_pkcs12 "github.com/tjfoc/gmsm/pkcs12"

    cryptobin_pkcs12 "github.com/deatil/go-cryptobin/pkcs12"
)

// 证书
func (this CA) FromCert(cert *x509.Certificate) CA {
    this.cert = cert

    return this
}

// 解析证书导入
func (this CA) FromCertificateDer(der []byte) CA {
    cert, err := x509.ParseCertificate(der)
    if err != nil {
        return this.AppendError(err)
    }

    this.cert = cert

    return this
}

// 证书请求
func (this CA) FromCertRequest(cert *x509.CertificateRequest) CA {
    this.certRequest = cert

    return this
}

// 解析证书导入
func (this CA) FromCertificateRequestDer(asn1Data []byte) CA {
    certRequest, err := x509.ParseCertificateRequest(asn1Data)
    if err != nil {
        return this.AppendError(err)
    }

    this.certRequest = certRequest

    return this
}

// 私钥
// 可用 [*rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey]
func (this CA) FromPrivateKey(key any) CA {
    this.privateKey = key

    return this
}

// 公钥
// 可用 [*rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey]
func (this CA) FromPublicKey(key any) CA {
    this.publicKey = key

    return this
}

// =======================

// pkcs12
func (this CA) FromSM2PKCS12Cert(pfxData []byte, password string) CA {
    pv, certs, err := sm2_pkcs12.DecodeAll(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    switch k := pv.(type) {
        case *ecdsa.PrivateKey:
            switch k.Curve {
                case sm2.P256Sm2():
                    sm2pub := &sm2.PublicKey{
                        Curve: k.Curve,
                        X:     k.X,
                        Y:     k.Y,
                    }

                    sm2Pri := &sm2.PrivateKey{
                        PublicKey: *sm2pub,
                        D:         k.D,
                    }

                    if !k.IsOnCurve(k.X, k.Y) {
                        err := errors.New("error while validating SM2 private key: %v")
                        return this.AppendError(err)
                    }

                    this.privateKey = sm2Pri
                    this.cert = certs[0]

                    return this
                default:
                    // other
            }
        default:
            // other
    }

    err = errors.New("unexpected type for p12 private key")

    return this.AppendError(err)
}

// pkcs12
func (this CA) FromSM2PKCS12OneCert(pfxData []byte, password string) CA {
    pv, cert, err := sm2_pkcs12.Decode(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    switch k := pv.(type) {
        case *ecdsa.PrivateKey:
            switch k.Curve {
                case sm2.P256Sm2():
                    sm2pub := &sm2.PublicKey{
                        Curve: k.Curve,
                        X:     k.X,
                        Y:     k.Y,
                    }

                    sm2Pri := &sm2.PrivateKey{
                        PublicKey: *sm2pub,
                        D:         k.D,
                    }

                    if !k.IsOnCurve(k.X, k.Y) {
                        err := errors.New("error while validating SM2 private key: %v")
                        return this.AppendError(err)
                    }

                    this.privateKey = sm2Pri
                    this.cert = cert

                    return this
                default:
                    // other
            }
        default:
            // other
    }

    err = errors.New("unexpected type for p12 private key")

    return this.AppendError(err)
}

// pkcs12
func (this CA) FromPKCS12Cert(pfxData []byte, password string) CA {
    privateKey, cert, err := cryptobin_pkcs12.Decode(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.cert = cert

    return this
}

// 解析 pkcs12 cert
func (this CA) DecodePKCS12CertChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
    privateKey, certificate, caCerts, err = cryptobin_pkcs12.DecodeChain(pfxData, password)

    return
}

// 解析 pkcs12 cert
func (this CA) DecodePKCS12CertTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
    certs, err = cryptobin_pkcs12.DecodeTrustStore(pfxData, password)

    return
}

// =======================

// 生成密钥 RSA
// bits = 512 | 1024 | 2048 | 4096
func (this CA) GenerateRsaKey(bits int) CA {
    // 生成私钥
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥 Ecdsa
// 可选 [P521 | P384 | P256 | P224]
func (this CA) GenerateEcdsaKey(curve string) CA {
    var useCurve elliptic.Curve

    switch {
        case curve == "P521":
            useCurve = elliptic.P521()
        case curve == "P384":
            useCurve = elliptic.P384()
        case curve == "P256":
            useCurve = elliptic.P256()
        case curve == "P224":
            useCurve = elliptic.P224()
        default:
            useCurve = elliptic.P256()
    }

    // 生成私钥
    privateKey, err := ecdsa.GenerateKey(useCurve, rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥 EdDSA
func (this CA) GenerateEdDSAKey() CA {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey  = publicKey
    this.privateKey = privateKey

    return this
}

// 生成密钥 SM2
func (this CA) GenerateSM2Key() CA {
    // 生成私钥
    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}
