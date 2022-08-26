package sign

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ed25519"
    "encoding/asn1"
)

// EdDsa 签名
type KeySignWithEdDsa struct {
    hashFunc   crypto.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithEdDsa) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithEdDsa) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithEdDsa) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv ed25519.PrivateKey
    var ok bool

    if priv, ok = pkey.(ed25519.PrivateKey); !ok {
        return nil, nil, errors.New("pkcs7: PrivateKey is not ed25519 PrivateKey")
    }

    hashData := hashSignData(this.hashFunc, data)

    signData, err := priv.Sign(rand.Reader, hashData, crypto.Hash(0))
    if err != nil {
        return nil, nil, err
    }

    return hashData, signData, nil
}

// 验证
func (this KeySignWithEdDsa) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub ed25519.PublicKey
    var ok bool

    if pub, ok = pkey.(ed25519.PublicKey); !ok {
        return false, errors.New("pkcs7: PublicKey is not ed25519 PublicKey")
    }

    hashData := hashSignData(this.hashFunc, signed)

    return ed25519.Verify(pub, hashData, signature), nil
}
