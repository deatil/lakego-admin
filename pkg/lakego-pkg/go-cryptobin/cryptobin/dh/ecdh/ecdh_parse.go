package ecdh

import (
    "errors"
    "crypto"
    "encoding/pem"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"

    "github.com/deatil/go-cryptobin/dh/ecdh"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotPrivateKey       = errors.New("key is not a valid ecdh private key")
    ErrNotPublicKey        = errors.New("key is not a valid ecdh public key")
)

// 解析私钥
func (this Ecdh) ParsePrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = ecdh.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *ecdh.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdh.PrivateKey); !ok {
        return nil, ErrNotPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this Ecdh) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var parsedKey any

    var blockDecrypted []byte
    if blockDecrypted, err = cryptobin_pkcs8.DecryptPKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
        if blockDecrypted, err = cryptobin_pkcs8pbe.DecryptPKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
            return nil, err
        }
    }

    if parsedKey, err = ecdh.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *ecdh.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdh.PrivateKey); !ok {
        return nil, ErrNotPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this Ecdh) ParsePublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = ecdh.ParsePublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *ecdh.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdh.PublicKey); !ok {
        return nil, ErrNotPublicKey
    }

    return pkey, nil
}
