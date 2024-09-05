package ed448

import (
    "errors"
    "crypto"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/ed448"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS8 key")
    ErrNotEdPrivateKey     = errors.New("key is not a valid ED448 private key")
    ErrNotEdPublicKey      = errors.New("key is not a valid ED448 public key")
)

// 解析私钥
func (this ED448) ParsePrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = ed448.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey ed448.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed448.PrivateKey); !ok {
        return nil, ErrNotEdPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this ED448) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
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

    var parsedKey any
    if parsedKey, err = ed448.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey ed448.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed448.PrivateKey); !ok {
        return nil, ErrNotEdPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this ED448) ParsePublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = ed448.ParsePublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey ed448.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(ed448.PublicKey); !ok {
        return nil, ErrNotEdPublicKey
    }

    return pkey, nil
}
