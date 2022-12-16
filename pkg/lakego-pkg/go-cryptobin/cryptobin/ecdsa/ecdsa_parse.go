package ecdsa

import (
    "errors"
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/pem"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPublicKey      = errors.New("key is not a valid ECDSA public key")
    ErrNotECPrivateKey     = errors.New("key is not a valid ECDSA private key")
)

// 解析私钥
func (this Ecdsa) ParsePrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
        if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
            return nil, err
        }
    }

    var pkey *ecdsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this Ecdsa) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = x509.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParseECPrivateKey(blockDecrypted); err != nil {
        if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
            return nil, err
        }
    }

    var pkey *ecdsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this Ecdsa) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*ecdsa.PrivateKey, error) {
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

    var pkey *ecdsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this Ecdsa) ParsePublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
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

    var pkey *ecdsa.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
        return nil, ErrNotECPublicKey
    }

    return pkey, nil
}
