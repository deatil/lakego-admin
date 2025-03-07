package ecgdsa

import (
    "errors"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/pubkey/ecgdsa"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPublicKey      = errors.New("key is not a valid ECGDSA public key")
    ErrNotECPrivateKey     = errors.New("key is not a valid ECGDSA private key")
)

// 解析私钥
func (this ECGDSA) ParsePKCS1PrivateKeyFromPEM(key []byte) (*ecgdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *ecgdsa.PrivateKey
    if pkey, err = ecgdsa.ParseECPrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析私钥带密码
func (this ECGDSA) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*ecgdsa.PrivateKey, error) {
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
    var pkey *ecgdsa.PrivateKey
    if pkey, err = ecgdsa.ParseECPrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析私钥
func (this ECGDSA) ParsePKCS8PrivateKeyFromPEM(key []byte) (*ecgdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *ecgdsa.PrivateKey
    if pkey, err = ecgdsa.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this ECGDSA) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*ecgdsa.PrivateKey, error) {
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

    var pkey *ecgdsa.PrivateKey
    if pkey, err = ecgdsa.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析公钥
func (this ECGDSA) ParsePublicKeyFromPEM(key []byte) (*ecgdsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = ecgdsa.ParsePublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *ecgdsa.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*ecgdsa.PublicKey); !ok {
        return nil, ErrNotECPublicKey
    }

    return pkey, nil
}
