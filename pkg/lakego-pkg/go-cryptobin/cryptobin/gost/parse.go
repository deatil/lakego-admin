package gost

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/gost"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS8 key")
    ErrNotGostPrivateKey   = errors.New("key is not a valid Gost private key")
    ErrNotGostPublicKey    = errors.New("key is not a valid Gost public key")
)

// 解析私钥
func (this Gost) ParsePrivateKeyFromPEM(key []byte) (*gost.PrivateKey, error) {
    // Parse PEM block
    block, _ := pem.Decode(key)
    if block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    pkey, err := gost.ParsePrivateKey(block.Bytes)
    if err != nil {
        return nil, ErrNotGostPrivateKey
    }

    return pkey, nil
}

// 解析带密码的私钥
func (this Gost) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*gost.PrivateKey, error) {
    // Parse PEM block
    block, _ := pem.Decode(key)
    if block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    blockDecrypted, err := pkcs8.DecryptPEMBlock(block, []byte(password))
    if err != nil {
        return nil, err
    }

    pkey, err := gost.ParsePrivateKey(blockDecrypted)
    if err != nil {
        return nil, ErrNotGostPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this Gost) ParsePublicKeyFromPEM(key []byte) (*gost.PublicKey, error) {
    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    pkey, err := gost.ParsePublicKey(block.Bytes)
    if err != nil {
        return nil, ErrNotGostPublicKey
    }

    return pkey, nil
}
