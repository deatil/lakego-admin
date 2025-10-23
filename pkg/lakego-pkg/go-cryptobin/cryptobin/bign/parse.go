package bign

import (
    "errors"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/bign"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("go-cryptobin/bign: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPublicKey      = errors.New("go-cryptobin/bign: key is not a valid Bign public key")
)

// 解析私钥
func (this Bign) ParsePKCS1PrivateKeyFromPEM(key []byte) (*bign.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *bign.PrivateKey
    if pkey, err = bign.ParseECPrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析私钥带密码
func (this Bign) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*bign.PrivateKey, error) {
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
    var pkey *bign.PrivateKey
    if pkey, err = bign.ParseECPrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析私钥
func (this Bign) ParsePKCS8PrivateKeyFromPEM(key []byte) (*bign.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *bign.PrivateKey
    if pkey, err = bign.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this Bign) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*bign.PrivateKey, error) {
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

    var pkey *bign.PrivateKey
    if pkey, err = bign.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析公钥
func (this Bign) ParsePublicKeyFromPEM(key []byte) (*bign.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = bign.ParsePublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *bign.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*bign.PublicKey); !ok {
        return nil, ErrNotECPublicKey
    }

    return pkey, nil
}
