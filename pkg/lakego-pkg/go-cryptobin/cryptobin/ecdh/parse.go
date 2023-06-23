package ecdh

import (
    "errors"
    "crypto"
    "crypto/x509"
    "crypto/ecdh"
    "crypto/ecdsa"
    "encoding/pem"

    cryptobin_ecdh "github.com/deatil/go-cryptobin/ecdh"
    cryptobin_pkcs8s "github.com/deatil/go-cryptobin/pkcs8s"
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
    if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    switch pkey := parsedKey.(type) {
        case *ecdh.PrivateKey:
            return pkey, nil
        case *ecdsa.PrivateKey:
            priKey, err := pkey.ECDH()
            if err != nil {
                return nil, err
            }

            return priKey, nil
    }

    return nil, ErrNotPrivateKey
}

// 解析私钥带密码
func (this Ecdh) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
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
    if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    switch pkey := parsedKey.(type) {
        case *ecdh.PrivateKey:
            return pkey, nil
        case *ecdsa.PrivateKey:
            priKey, err := pkey.ECDH()
            if err != nil {
                return nil, err
            }

            return priKey, nil
    }

    return nil, ErrNotPrivateKey
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
    if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    switch pkey := parsedKey.(type) {
        case *ecdh.PublicKey:
            return pkey, nil
        case *ecdsa.PublicKey:
            pubKey, err := pkey.ECDH()
            if err != nil {
                return nil, err
            }

            return pubKey, nil
    }

    return nil, ErrNotPublicKey
}

// ==========================================

// 解析私钥
func (this Ecdh) ParseECDHPrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_ecdh.ParsePrivateKey(block.Bytes); err != nil {
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
func (this Ecdh) ParseECDHPrivateKeyFromPEMWithPassword(key []byte, password string) (crypto.PrivateKey, error) {
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
    if parsedKey, err = cryptobin_ecdh.ParsePrivateKey(blockDecrypted); err != nil {
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
func (this Ecdh) ParseECDHPublicKeyFromPEM(key []byte) (crypto.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_ecdh.ParsePublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *ecdh.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*ecdh.PublicKey); !ok {
        return nil, ErrNotPublicKey
    }

    return pkey, nil
}
