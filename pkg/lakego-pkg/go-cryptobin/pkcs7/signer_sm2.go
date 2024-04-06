package pkcs7

import (
    "hash"
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ecdsa"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// sm2 签名
type KeySignWithSM2 struct {
    hashFunc   func() hash.Hash
    hashId     asn1.ObjectIdentifier
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeySignWithSM2) HashOID() asn1.ObjectIdentifier {
    return this.hashId
}

// oid
func (this KeySignWithSM2) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 签名
func (this KeySignWithSM2) Sign(pkey crypto.PrivateKey, data []byte) ([]byte, []byte, error) {
    var priv *sm2.PrivateKey
    var ok bool

    if priv, ok = pkey.(*sm2.PrivateKey); !ok {
        return nil, nil, errors.New("pkcs7: PrivateKey is not sm2 PrivateKey")
    }

    signData, err := priv.Sign(rand.Reader, data, nil)

    return nil, signData, err
}

// 验证
func (this KeySignWithSM2) Verify(pkey crypto.PublicKey, signed []byte, signature []byte) (bool, error) {
    var pub *sm2.PublicKey

    switch k := pkey.(type) {
        case *sm2.PublicKey:
            pub = k
        case *ecdsa.PublicKey:
            switch k.Curve {
                case sm2.P256():
                    pub = &sm2.PublicKey{
                        Curve: k.Curve,
                        X:     k.X,
                        Y:     k.Y,
                    }

                    if !k.IsOnCurve(k.X, k.Y) {
                        return false, errors.New("pkcs7: error while validating SM2 public key: %v")
                    }
            }
        default:
            return false, errors.New("pkcs7: PublicKey is not sm2 PublicKey")
    }

    return pub.Verify(signed, signature, nil), nil
}

// 检测证书
func (this KeySignWithSM2) Check(pkey any) bool {
    if _, ok := pkey.(*sm2.PrivateKey); ok {
        return true
    }

    if _, ok := pkey.(*sm2.PublicKey); ok {
        return true
    }

    return false
}
