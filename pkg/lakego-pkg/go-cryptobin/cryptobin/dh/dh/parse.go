package dh

import (
    "errors"
    "crypto"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/dh/dh"

    cryptobin_pkcs8s "github.com/deatil/go-cryptobin/pkcs8s"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotPrivateKey       = errors.New("key is not a valid dh private key")
    ErrNotPublicKey        = errors.New("key is not a valid dh public key")
)

// 解析私钥
func (this Dh) ParsePrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = dh.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *dh.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*dh.PrivateKey); !ok {
        return nil, ErrNotPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this Dh) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = cryptobin_pkcs8s.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    var parsedKey any
    if parsedKey, err = dh.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *dh.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*dh.PrivateKey); !ok {
        return nil, ErrNotPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this Dh) ParsePublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = dh.ParsePublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *dh.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*dh.PublicKey); !ok {
        return nil, ErrNotPublicKey
    }

    return pkey, nil
}
