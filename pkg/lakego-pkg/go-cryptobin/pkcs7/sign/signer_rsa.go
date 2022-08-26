package sign

import (
    "errors"
    "crypto"
    "crypto/rsa"
    "crypto/rand"
    "encoding/asn1"
)

// rsa 签名
type KeySignWithRsa struct {
    isRSAPSS   bool
    hashFunc   crypto.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithRsa) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithRsa) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithRsa) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv *rsa.PrivateKey
    var ok bool

    if priv, ok = pkey.(*rsa.PrivateKey); !ok {
        return nil, nil, errors.New("pkcs7: PrivateKey is not rsa PrivateKey")
    }

    hashType := this.hashFunc
    hashData := hashSignData(hashType, data)

    var signData []byte
    var err error

    if this.isRSAPSS {
        signData, err = rsa.SignPSS(rand.Reader, priv, hashType, hashData, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
    } else {
        signData, err = rsa.SignPKCS1v15(rand.Reader, priv, hashType, hashData)
    }

    return hashData, signData, err
}

// 验证
func (this KeySignWithRsa) Verify(pkey crypto.PublicKey, data []byte, signature []byte) (bool, error) {
    var pub *rsa.PublicKey
    var ok bool

    if pub, ok = pkey.(*rsa.PublicKey); !ok {
        return false, errors.New("pkcs7: PublicKey is not rsa PublicKey")
    }

    hashType := this.hashFunc
    hashData := hashSignData(hashType, data)

    var err error

    if this.isRSAPSS {
        err = rsa.VerifyPSS(pub, hashType, hashData, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
    } else {
        err = rsa.VerifyPKCS1v15(pub, hashType, hashData, signature)
    }

    if err != nil {
        return false, err
    }

    return true, nil
}
