package sign

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ecdsa"
    "encoding/asn1"
)

// ecdsa 签名
type KeySignWithEcdsa struct {
    hashFunc   crypto.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithEcdsa) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithEcdsa) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithEcdsa) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv *ecdsa.PrivateKey
    var ok bool

    if priv, ok = pkey.(*ecdsa.PrivateKey); !ok {
        return nil, nil, errors.New("pkcs7: PrivateKey is not ecdsa PrivateKey")
    }

    hashData := hashSignData(this.hashFunc, data)

    signData, err := ecdsa.SignASN1(rand.Reader, priv, hashData)

    return hashData, signData, err
}

// 验证
func (this KeySignWithEcdsa) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub *ecdsa.PublicKey
    var ok bool

    if pub, ok = pkey.(*ecdsa.PublicKey); !ok {
        return false, errors.New("pkcs7: PublicKey is not ecdsa PublicKey")
    }

    hashData := hashSignData(this.hashFunc, signed)

    return ecdsa.VerifyASN1(pub, hashData, signature), nil
}
