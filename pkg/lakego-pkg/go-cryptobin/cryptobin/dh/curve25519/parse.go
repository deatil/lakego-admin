package curve25519

import (
    "errors"
    "crypto"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/dh/curve25519"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotPrivateKey       = errors.New("key is not a valid curve25519 private key")
    ErrNotPublicKey        = errors.New("key is not a valid curve25519 public key")
)

// 解析私钥
func (this Curve25519) ParsePrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = curve25519.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *curve25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*curve25519.PrivateKey); !ok {
        return nil, ErrNotPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this Curve25519) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
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
    if parsedKey, err = curve25519.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *curve25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*curve25519.PrivateKey); !ok {
        return nil, ErrNotPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this Curve25519) ParsePublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = curve25519.ParsePublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *curve25519.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*curve25519.PublicKey); !ok {
        return nil, ErrNotPublicKey
    }

    return pkey, nil
}
