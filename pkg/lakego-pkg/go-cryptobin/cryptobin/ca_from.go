package cryptobin

import (
    "errors"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"

    "github.com/tjfoc/gmsm/sm2"
    sm2Pkcs12 "github.com/tjfoc/gmsm/pkcs12"
    sslmatePkcs12 "software.sslmate.com/src/go-pkcs12"
)

// 证书
func (this CA) FromCert(cert *x509.Certificate) CA {
    this.cert = cert

    return this
}

// 解析证书导入
func (this CA) FromCertificateDer(der []byte) CA {
    this.cert, this.Error = x509.ParseCertificate(der)

    return this
}

// 证书请求
func (this CA) FromCertRequest(cert *x509.CertificateRequest) CA {
    this.certRequest = cert

    return this
}

// 解析证书导入
func (this CA) FromCertificateRequestDer(asn1Data []byte) CA {
    this.certRequest, this.Error = x509.ParseCertificateRequest(asn1Data)

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
    pv, certs, err := sm2Pkcs12.DecodeAll(pfxData, password)
    if err != nil {
        this.Error = err
        return this
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
                        this.Error = errors.New("error while validating SM2 private key: %v")
                        return this
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

    this.Error = errors.New("unexpected type for p12 private key")

    return this
}

// pkcs12
func (this CA) FromSM2PKCS12OneCert(pfxData []byte, password string) CA {
    pv, cert, err := sm2Pkcs12.Decode(pfxData, password)
    if err != nil {
        this.Error = err
        return this
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
                        this.Error = errors.New("error while validating SM2 private key: %v")
                        return this
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

    this.Error = errors.New("unexpected type for p12 private key")

    return this
}

// pkcs12
func (this CA) FromPKCS12Cert(pfxData []byte, password string) CA {
    this.privateKey, this.cert, this.Error = sslmatePkcs12.Decode(pfxData, password)

    return this
}

// 解析 pkcs12 cert
func (this CA) DecodePKCS12CertChain(pfxData []byte, password string) (privateKey interface{}, certificate *x509.Certificate, caCerts []*x509.Certificate, err error) {
    privateKey, certificate, caCerts, err = sslmatePkcs12.DecodeChain(pfxData, password)

    return
}

// 解析 pkcs12 cert
func (this CA) DecodePKCS12CertTrustStore(pfxData []byte, password string) (certs []*x509.Certificate, err error) {
    certs, err = sslmatePkcs12.DecodeTrustStore(pfxData, password)

    return
}

// =======================

// 生成密钥 RSA
// bits = 512 | 1024 | 2048 | 4096
func (this CA) GenerateRsaKey(bits int) CA {
    // 生成私钥
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)

    this.privateKey = privateKey
    this.Error = err

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

    this.privateKey = privateKey
    this.Error = err

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}

// 生成密钥 EdDSA
func (this CA) GenerateEdDSAKey() CA {
    this.publicKey, this.privateKey, this.Error = ed25519.GenerateKey(rand.Reader)

    return this
}

// 生成密钥 SM2
func (this CA) GenerateSM2Key() CA {
    // 生成私钥
    privateKey, err := sm2.GenerateKey(rand.Reader)

    this.privateKey = privateKey
    this.Error = err

    // 生成公钥
    this.publicKey = &privateKey.PublicKey

    return this
}
