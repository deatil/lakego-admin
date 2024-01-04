package encrypt

import (
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/ecdsa"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// key 用 sm2 加密
type KeyEncryptWithSM2 struct {
    identifier asn1.ObjectIdentifier
}

// oid
func (this KeyEncryptWithSM2) OID() asn1.ObjectIdentifier {
    return this.identifier
}

// 加密
func (this KeyEncryptWithSM2) Encrypt(plaintext []byte, pkey crypto.PublicKey) ([]byte, error) {
    var pub *sm2.PublicKey

    switch k := pkey.(type) {
        case *sm2.PublicKey:
            pub = k
        case *ecdsa.PublicKey:
            switch k.Curve {
                case sm2.P256Sm2():
                    pub = &sm2.PublicKey{
                        Curve: k.Curve,
                        X:     k.X,
                        Y:     k.Y,
                    }

                    if !k.IsOnCurve(k.X, k.Y) {
                        return nil, errors.New("pkcs7: error while validating SM2 public key: %v")
                    }
            }
        default:
            return nil, errors.New("pkcs7: PublicKey is not sm2 PublicKey")
    }

    return sm2.EncryptASN1(rand.Reader, pub, plaintext, sm2.C1C3C2)
}

// 解密
func (this KeyEncryptWithSM2) Decrypt(ciphertext []byte, pkey crypto.PrivateKey) ([]byte, error) {
    var priv *sm2.PrivateKey
    var ok bool

    if priv, ok = pkey.(*sm2.PrivateKey); !ok {
        return nil, errors.New("pkcs7: PrivateKey is not sm2 PrivateKey")
    }

    return sm2.DecryptASN1(priv, ciphertext, sm2.C1C3C2)
}
