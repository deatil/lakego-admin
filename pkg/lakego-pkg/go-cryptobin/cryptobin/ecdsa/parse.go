package ecdsa

import (
    "errors"
    "crypto/x509"
    "crypto/ecdsa"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    pubkey_ecdsa "github.com/deatil/go-cryptobin/pubkey/ecdsa"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("go-cryptobin/ecdsa: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPublicKey      = errors.New("go-cryptobin/ecdsa: key is not a valid ECDSA public key")
    ErrNotECPrivateKey     = errors.New("go-cryptobin/ecdsa: key is not a valid ECDSA private key")
)

// 解析私钥
func (this ECDSA) ParsePKCS1PrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    pkey, err := pubkey_ecdsa.ParseECPrivateKey(block.Bytes)
    if err != nil {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this ECDSA) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = pkcs1.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    // Parse the key
    var pkey *ecdsa.PrivateKey
    if pkey, err = pubkey_ecdsa.ParseECPrivateKey(blockDecrypted); err != nil {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// ==========

// 解析私钥
func (this ECDSA) ParsePKCS8PrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *ecdsa.PrivateKey
    if pkey, err = pubkey_ecdsa.ParsePrivateKey(block.Bytes); err != nil {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this ECDSA) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = pkcs8.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    var pkey *ecdsa.PrivateKey
    if pkey, err = pubkey_ecdsa.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析公钥
func (this ECDSA) ParsePublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = pubkey_ecdsa.ParsePublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *ecdsa.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
        return nil, ErrNotECPublicKey
    }

    return pkey, nil
}
