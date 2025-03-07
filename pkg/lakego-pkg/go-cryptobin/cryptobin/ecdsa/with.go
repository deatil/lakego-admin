package ecdsa

import (
    "encoding/asn1"
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/tool/hash"
    pubkey_ecdsa "github.com/deatil/go-cryptobin/pubkey/ecdsa"
)

// Add Named Curve
func (this ECDSA) AddNamedCurve(curve elliptic.Curve, oid asn1.ObjectIdentifier) ECDSA {
    pubkey_ecdsa.AddNamedCurve(curve, oid)
    return this
}

// Add Named Curve
func AddNamedCurve(curve elliptic.Curve, oid asn1.ObjectIdentifier) ECDSA {
    return defaultECDSA.AddNamedCurve(curve, oid)
}

// With PrivateKey
func (this ECDSA) WithPrivateKey(data *ecdsa.PrivateKey) ECDSA {
    this.privateKey = data

    return this
}

// With PublicKey
func (this ECDSA) WithPublicKey(data *ecdsa.PublicKey) ECDSA {
    this.publicKey = data

    return this
}

// With curve
func (this ECDSA) WithCurve(curve elliptic.Curve) ECDSA {
    this.curve = curve

    return this
}

// set curve
// params [P521 | P384 | P256 | P224]
func (this ECDSA) SetCurve(curve string) ECDSA {
    switch curve {
        case "P521":
            this.curve = elliptic.P521()
        case "P384":
            this.curve = elliptic.P384()
        case "P256":
            this.curve = elliptic.P256()
        case "P224":
            this.curve = elliptic.P224()
    }

    return this
}

// With hash type
func (this ECDSA) WithSignHash(hash HashFunc) ECDSA {
    this.signHash = hash

    return this
}

// With hash type
func (this ECDSA) SetSignHash(name string) ECDSA {
    h, err := hash.GetHash(name)
    if err != nil {
        return this.AppendError(err)
    }

    this.signHash = h

    return this
}

// With data
func (this ECDSA) WithData(data []byte) ECDSA {
    this.data = data

    return this
}

// With parsedData
func (this ECDSA) WithParsedData(data []byte) ECDSA {
    this.parsedData = data

    return this
}

// With encoding
func (this ECDSA) WithEncoding(encoding EncodingType) ECDSA {
    this.encoding = encoding

    return this
}

// encoding ASN1 encoding type
func (this ECDSA) WithEncodingASN1() ECDSA {
    return this.WithEncoding(EncodingASN1)
}

// encoding Bytes encoding type
func (this ECDSA) WithEncodingBytes() ECDSA {
    return this.WithEncoding(EncodingBytes)
}

// WithVerify
func (this ECDSA) WithVerify(data bool) ECDSA {
    this.verify = data

    return this
}

// WithErrors
func (this ECDSA) WithErrors(errs []error) ECDSA {
    this.Errors = errs

    return this
}
