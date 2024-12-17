package pkcs7

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ecdsa"
    "encoding/asn1"
)

// ecdsa 签名
type KeySignWithECDSA struct {
    hashFunc   crypto.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithECDSA) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithECDSA) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithECDSA) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv *ecdsa.PrivateKey
    var ok bool

    if priv, ok = pkey.(*ecdsa.PrivateKey); !ok {
        return nil, nil, errors.New("go-cryptobin/pkcs7: PrivateKey is not ecdsa PrivateKey")
    }

    hashData := hashSignData(this.hashFunc, data)

    signData, err := ecdsa.SignASN1(rand.Reader, priv, hashData)

    return hashData, signData, err
}

// 验证
func (this KeySignWithECDSA) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub *ecdsa.PublicKey
    var ok bool

    if pub, ok = pkey.(*ecdsa.PublicKey); !ok {
        return false, errors.New("go-cryptobin/pkcs7: PublicKey is not ecdsa PublicKey")
    }

    hashData := hashSignData(this.hashFunc, signed)

    return ecdsa.VerifyASN1(pub, hashData, signature), nil
}

// 检测证书
func (this KeySignWithECDSA) Check(pkey any) bool {
    if _, ok := pkey.(*ecdsa.PrivateKey); ok {
        return true
    }

    if _, ok := pkey.(*ecdsa.PublicKey); ok {
        return true
    }

    return false
}
