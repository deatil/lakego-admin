package eddsa

import (
    "errors"
    "crypto"
    "crypto/x509"
    "crypto/ed25519"
    "encoding/pem"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotEdPrivateKey     = errors.New("key is not a valid Ed25519 private key")
    ErrNotEdPublicKey      = errors.New("key is not a valid Ed25519 public key")
)

// 解析私钥
func (this EdDSA) ParsePrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey ed25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
        return nil, ErrNotEdPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this EdDSA) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
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

    if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey ed25519.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PrivateKey); !ok {
        return nil, ErrNotEdPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this EdDSA) ParsePublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey ed25519.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(ed25519.PublicKey); !ok {
        return nil, ErrNotEdPublicKey
    }

    return pkey, nil
}
