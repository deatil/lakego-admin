package ca

import (
    "io"
    "errors"
    "crypto/rand"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/x509"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/pkcs12"
)

// Generate Key with Reader
func (this CA) GenerateKeyWithSeed(reader io.Reader) CA {
    switch this.options.PublicKeyType {
        case KeyTypeRSA:
            privateKey, err := rsa.GenerateKey(reader, this.options.Bits)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
        case KeyTypeDSA:
            privateKey := &dsa.PrivateKey{}
            dsa.GenerateParameters(&privateKey.Parameters, reader, this.options.ParameterSizes)
            dsa.GenerateKey(privateKey, reader)

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
        case KeyTypeECDSA:
            privateKey, err := ecdsa.GenerateKey(this.options.Curve, reader)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey = &privateKey.PublicKey
        case KeyTypeEdDSA:
            publicKey, privateKey, err := ed25519.GenerateKey(reader)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = publicKey
        case KeyTypeSM2:
            privateKey, err := sm2.GenerateKey(reader)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
    }

    return this
}

// Generate Key with Reader
func GenerateKeyWithSeed(reader io.Reader, options ...Options) CA {
    if len(options) > 0 {
        return defaultCA.
            WithOptions(options[0]).
            GenerateKeyWithSeed(reader)
    }

    return defaultCA.GenerateKeyWithSeed(reader)
}

// Generate Key
func (this CA) GenerateKey() CA {
    return this.GenerateKeyWithSeed(rand.Reader)
}

// Generate Key
func GenerateKey(options ...Options) CA {
    if len(options) > 0 {
        return defaultCA.
            WithOptions(options[0]).
            GenerateKey()
    }

    return defaultCA.GenerateKey()
}

// ==========

// From Certificate
func (this CA) FromCertificate(der []byte) CA {
    cert, err := x509.ParseCertificate(der)
    if err != nil {
        return this.AppendError(err)
    }

    this.cert = cert

    return this
}

// From Certificate
func FromCertificate(der []byte) CA {
    return defaultCA.FromCertificate(der)
}

// From Certificate Request
func (this CA) FromCertificateRequest(asn1Data []byte) CA {
    certRequest, err := x509.ParseCertificateRequest(asn1Data)
    if err != nil {
        return this.AppendError(err)
    }

    this.certRequest = certRequest

    return this
}

// From Certificate Request
func FromCertificateRequest(asn1Data []byte) CA {
    return defaultCA.FromCertificateRequest(asn1Data)
}

// From PrivateKey
func (this CA) FromPrivateKey(key []byte) CA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey
func FromPrivateKey(key []byte) CA {
    return defaultCA.FromPrivateKey(key)
}

// From PrivateKey With Password
func (this CA) FromPrivateKeyWithPassword(key []byte, password []byte) CA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey With Password
func FromPrivateKeyWithPassword(key []byte, password []byte) CA {
    return defaultCA.FromPrivateKeyWithPassword(key, password)
}

// From PublicKey
func (this CA) FromPublicKey(key []byte) CA {
    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// From PublicKey
func FromPublicKey(key []byte) CA {
    return defaultCA.FromPublicKey(key)
}

// ==========

// pkcs12
func (this CA) FromPKCS12Cert(pfxData []byte, password string) CA {
    privateKey, cert, err := pkcs12.Decode(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey
    this.cert = cert

    return this
}

// From PKCS12 Cert
func FromPKCS12Cert(pfxData []byte, password string) CA {
    return defaultCA.FromPKCS12Cert(pfxData, password)
}

// From SM2 PKCS12 Cert
func (this CA) FromSM2PKCS12Cert(pfxData []byte, password string) CA {
    pv, cert, err := pkcs12.Decode(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    switch k := pv.(type) {
        case *ecdsa.PrivateKey:
            switch k.Curve {
                case sm2.P256():
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

// From SM2 PKCS12 Cert
func FromSM2PKCS12Cert(pfxData []byte, password string) CA {
    return defaultCA.FromSM2PKCS12Cert(pfxData, password)
}

// =======================

// Generate RSA key
// params:
// [512 | 1024 | 2048 | 4096]
func (this CA) GenerateRSAKey(bits int) CA {
    return this.SetPublicKeyType("RSA").
            WithBits(bits).
            GenerateKey()
}

// Generate RSA Key
func GenerateRSAKey(bits int) CA {
    return defaultCA.GenerateRSAKey(bits)
}

// Generate DSA key
// params:
// [ L1024N160 | L2048N224 | L2048N256 | L3072N256 ]
func (this CA) GenerateDSAKey(ln string) CA {
    return this.SetPublicKeyType("DSA").
            SetCurve(ln).
            GenerateKey()

}

// Generate DSA Key
func GenerateDSAKey(ln string) CA {
    return defaultCA.GenerateDSAKey(ln)
}

// Generate ECDSA key
// params:
// [P521 | P384 | P256 | P224]
func (this CA) GenerateECDSAKey(curve string) CA {
    return this.SetPublicKeyType("ECDSA").
            SetCurve(curve).
            GenerateKey()

}

// Generate ECDSA Key
func GenerateECDSAKey(curve string) CA {
    return defaultCA.GenerateECDSAKey(curve)
}

// Generate EdDSA key
func (this CA) GenerateEdDSAKey() CA {
    return this.SetPublicKeyType("EdDSA").
            GenerateKey()

}

// Generate EdDSA Key
func GenerateEdDSAKey() CA {
    return defaultCA.GenerateEdDSAKey()
}

// Generate SM2 key
func (this CA) GenerateSM2Key() CA {
    return this.SetPublicKeyType("SM2").
            GenerateKey()

}

// Generate SM2 Key
func GenerateSM2Key() CA {
    return defaultCA.GenerateSM2Key()
}
