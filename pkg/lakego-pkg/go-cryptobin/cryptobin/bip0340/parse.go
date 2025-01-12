package bip0340

import (
    "errors"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/bip0340"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPublicKey      = errors.New("key is not a valid BIP0340 public key")
    ErrNotECPrivateKey     = errors.New("key is not a valid BIP0340 private key")
)

// 解析私钥
func (this BIP0340) ParsePKCS1PrivateKeyFromPEM(key []byte) (*bip0340.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *bip0340.PrivateKey
    if pkey, err = bip0340.ParseECPrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析私钥带密码
func (this BIP0340) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*bip0340.PrivateKey, error) {
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
    var pkey *bip0340.PrivateKey
    if pkey, err = bip0340.ParseECPrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析私钥
func (this BIP0340) ParsePKCS8PrivateKeyFromPEM(key []byte) (*bip0340.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *bip0340.PrivateKey
    if pkey, err = bip0340.ParsePrivateKey(block.Bytes); err != nil {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this BIP0340) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*bip0340.PrivateKey, error) {
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

    var pkey *bip0340.PrivateKey
    if pkey, err = bip0340.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// ==========

// 解析公钥
func (this BIP0340) ParsePublicKeyFromPEM(key []byte) (*bip0340.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = bip0340.ParsePublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *bip0340.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*bip0340.PublicKey); !ok {
        return nil, ErrNotECPublicKey
    }

    return pkey, nil
}
