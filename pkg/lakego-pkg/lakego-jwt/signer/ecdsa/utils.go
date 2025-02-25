package ecdsa

import (
    "errors"
    "encoding/pem"
    "crypto/ecdsa"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
    pubkey_ecdsa "github.com/deatil/go-cryptobin/pubkey/ecdsa"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrKeyPasswordInvalid  = errors.New("invalid key: Key password error")
)

func init() {
    pubkey_ecdsa.AddNamedCurve(secp256k1.S256(), secp256k1.OIDNamedCurveSecp256k1)
}

// 解析 PKCS8 私钥
func ParsePrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var pkey *ecdsa.PrivateKey
    if pkey, err = pubkey_ecdsa.ParsePrivateKey(block.Bytes); err != nil {
        if pkey, err = pubkey_ecdsa.ParseECPrivateKey(block.Bytes); err != nil {
            return nil, ErrKeyMustBePEMEncoded
        }
    }

    return pkey, nil
}

// 解析 PKCS8 私钥带密码
func ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = pkcs8.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, ErrKeyPasswordInvalid
    }

    var pkey *ecdsa.PrivateKey
    if pkey, err = pubkey_ecdsa.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    return pkey, nil
}

// 解析 PKCS8 公钥
func ParsePublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var pkey *ecdsa.PublicKey
    if pkey, err = pubkey_ecdsa.ParsePublicKey(block.Bytes); err != nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    return pkey, nil
}
