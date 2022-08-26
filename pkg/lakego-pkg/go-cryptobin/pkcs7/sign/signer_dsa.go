package sign

import (
    "errors"
    "math/big"
    "crypto"
    "crypto/dsa"
    "crypto/rand"
    "encoding/asn1"
)

type dsaSignature struct {
    R, S *big.Int
}

// rsa 签名
type KeySignWithDSA struct {
    hashFunc   crypto.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithDSA) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithDSA) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithDSA) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv *dsa.PrivateKey
    var ok bool

    if priv, ok = pkey.(*dsa.PrivateKey); !ok {
        return nil, nil, errors.New("pkcs7: PrivateKey is not dsa PrivateKey")
    }

    hashData := hashSignData(this.hashFunc, data)

    r, s, err := dsa.Sign(rand.Reader, priv, hashData)
    if err != nil {
        return nil, nil, err
    }

    signData, err := asn1.Marshal(dsaSignature{r, s})
    if err != nil {
        return nil, nil, err
    }

    return hashData, signData, nil
}

// 验证
func (this KeySignWithDSA) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub *dsa.PublicKey
    var ok bool

    if pub, ok = pkey.(*dsa.PublicKey); !ok {
        return false, errors.New("pkcs7: PublicKey is not dsa PublicKey")
    }

    var dsaSign dsaSignature
    _, err := asn1.Unmarshal(signature, &dsaSign)
    if err != nil {
        return false, err
    }

    r := dsaSign.R
    s := dsaSign.S

    hashData := hashSignData(this.hashFunc, signed)

    return dsa.Verify(pub, hashData, r, s), nil
}
