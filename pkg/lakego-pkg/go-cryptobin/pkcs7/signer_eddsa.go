package pkcs7

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ed25519"
    "encoding/asn1"
)

// EdDsa 签名
type KeySignWithEdDSA struct {
    hashFunc   crypto.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithEdDSA) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithEdDSA) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithEdDSA) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv ed25519.PrivateKey
    var ok bool

    if priv, ok = pkey.(ed25519.PrivateKey); !ok {
        return nil, nil, errors.New("go-cryptobin/pkcs7: PrivateKey is not ed25519 PrivateKey")
    }

    isHash := false
    hashData := data
    if this.hashFunc == crypto.SHA512 {
        hashData = hashSignData(this.hashFunc, data)
        isHash = true
    }

    signData, err := priv.Sign(rand.Reader, hashData, crypto.Hash(0))
    if err != nil {
        return nil, nil, err
    }

    var hashedData []byte
    if isHash {
        hashedData = hashData
    }

    return hashedData, signData, nil
}

// 验证
func (this KeySignWithEdDSA) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub ed25519.PublicKey
    var ok bool

    if pub, ok = pkey.(ed25519.PublicKey); !ok {
        return false, errors.New("go-cryptobin/pkcs7: PublicKey is not ed25519 PublicKey")
    }

    hashData := signed
    if this.hashFunc == crypto.SHA512 {
        hashData = hashSignData(this.hashFunc, signed)
    }

    return ed25519.Verify(pub, hashData, signature), nil
}

// 检测证书
func (this KeySignWithEdDSA) Check(pkey any) bool {
    if _, ok := pkey.(ed25519.PrivateKey); ok {
        return true
    }

    if _, ok := pkey.(ed25519.PublicKey); ok {
        return true
    }

    return false
}
