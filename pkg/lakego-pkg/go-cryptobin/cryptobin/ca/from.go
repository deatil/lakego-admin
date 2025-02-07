package ca

import (
    "io"
    "crypto/rand"
    "crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/ed25519"

    "github.com/deatil/go-cryptobin/x509"
    "github.com/deatil/go-cryptobin/pkcs12"
    "github.com/deatil/go-cryptobin/gm/sm2"
    "github.com/deatil/go-cryptobin/pubkey/gost"
    "github.com/deatil/go-cryptobin/pubkey/elgamal"
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
        case KeyTypeGost:
            privateKey, err := gost.GenerateKey(reader, this.options.GostCurve)
            if err != nil {
                return this.AppendError(err)
            }

            this.privateKey = privateKey
            this.publicKey  = &privateKey.PublicKey
        case KeyTypeElGamal:
            privateKey, err := elgamal.GenerateKey(reader, this.options.Bitsize, this.options.Probability)
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

// From Certificate PEM
func (this CA) FromCertificate(cert []byte) CA {
    newCert, err := this.ParseCertificateFromPEM(cert)
    if err != nil {
        return this.AppendError(err)
    }

    this.cert = newCert
    this.publicKey = newCert.PublicKey

    return this
}

// From Certificate PEM
func FromCertificate(cert []byte) CA {
    return defaultCA.FromCertificate(cert)
}

// From Certificate Request PEM
func (this CA) FromCertificateRequest(cert []byte) CA {
    certRequest, err := this.ParseCertificateRequestFromPEM(cert)
    if err != nil {
        return this.AppendError(err)
    }

    this.certRequest = certRequest
    this.publicKey = certRequest.PublicKey

    return this
}

// From Certificate Request PEM
func FromCertificateRequest(cert []byte) CA {
    return defaultCA.FromCertificateRequest(cert)
}

// From PrivateKey PEM
func (this CA) FromPrivateKey(key []byte) CA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey PEM
func FromPrivateKey(key []byte) CA {
    return defaultCA.FromPrivateKey(key)
}

// From PrivateKey PEM With Password
func (this CA) FromPrivateKeyWithPassword(key []byte, password []byte) CA {
    privateKey, err := this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.privateKey = privateKey

    return this
}

// From PrivateKey PEM With Password
func FromPrivateKeyWithPassword(key []byte, password []byte) CA {
    return defaultCA.FromPrivateKeyWithPassword(key, password)
}

// From PublicKey PEM
func (this CA) FromPublicKey(key []byte) CA {
    publicKey, err := this.ParsePKCS8PublicKeyFromPEM(key)
    if err != nil {
        return this.AppendError(err)
    }

    this.publicKey = publicKey

    return this
}

// From PublicKey PEM
func FromPublicKey(key []byte) CA {
    return defaultCA.FromPublicKey(key)
}

// ==========

// pkcs12
func (this CA) FromPKCS12Cert(pfxData []byte, password string) CA {
    privateKey, cert, _, err := pkcs12.DecodeChain(pfxData, password)
    if err != nil {
        return this.AppendError(err)
    }

    this.cert = &x509.Certificate{}
    this.cert.FromX509Certificate(cert)

    this.privateKey = privateKey

    return this
}

// From PKCS12 Cert
func FromPKCS12Cert(pfxData []byte, password string) CA {
    return defaultCA.FromPKCS12Cert(pfxData, password)
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

// Generate Gost key
func (this CA) GenerateGostKey(curve string) CA {
    return this.SetPublicKeyType("Gost").
            SetGostCurve(curve).
            GenerateKey()
}

// Generate Gost Key
func GenerateGostKey(curve string) CA {
    return defaultCA.GenerateGostKey(curve)
}

// Generate ElGamal key
func (this CA) GenerateElGamalKey(bitsize, probability int) CA {
    return this.SetPublicKeyType("ElGamal").
            WithBitsize(bitsize).
            WithProbability(probability).
            GenerateKey()
}

// Generate ElGamal Key
func GenerateElGamalKey(bitsize, probability int) CA {
    return defaultCA.GenerateElGamalKey(bitsize, probability)
}
