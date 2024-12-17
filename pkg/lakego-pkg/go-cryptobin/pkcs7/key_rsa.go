package pkcs7

import (
    "hash"
    "errors"
    "crypto"
    "crypto/rsa"
    "crypto/rand"
    "encoding/asn1"
)

// key 用 rsa 加密
type KeyEncryptWithRSA struct {
    hashFunc   func() hash.Hash
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeyEncryptWithRSA) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this KeyEncryptWithRSA) Encrypt(plaintext []byte, pkey crypto.PublicKey) ([]byte, error) {
    var pub *rsa.PublicKey
    var ok bool

    if pub, ok = pkey.(*rsa.PublicKey); !ok {
        return nil, errors.New("go-cryptobin/pkcs7: PublicKey is not rsa PublicKey")
    }

    if this.hashFunc != nil {
        newHash := this.hashFunc
        return rsa.EncryptOAEP(newHash(), rand.Reader, pub, plaintext, nil)
    }

    return rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
}

// 解密
func (this KeyEncryptWithRSA) Decrypt(ciphertext []byte, pkey crypto.PrivateKey) ([]byte, error) {
    var priv *rsa.PrivateKey
    var ok bool

    if priv, ok = pkey.(*rsa.PrivateKey); !ok {
        return nil, errors.New("go-cryptobin/pkcs7: PrivateKey is not rsa PrivateKey")
    }

    if this.hashFunc != nil {
        newHash := this.hashFunc
        return rsa.DecryptOAEP(newHash(), rand.Reader, priv, ciphertext, nil)
    }

    return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// 检测证书
func (this KeyEncryptWithRSA) Check(pkey any) bool {
    if _, ok := pkey.(*rsa.PrivateKey); ok {
        return true
    }

    if _, ok := pkey.(*rsa.PublicKey); ok {
        return true
    }

    return false
}
