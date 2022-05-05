package cryptobin

import (
    "errors"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotRSAPrivateKey    = errors.New("key is not a valid RSA private key")
    ErrNotRSAPublicKey     = errors.New("key is not a valid RSA public key")
)

// 解析 PKCS1 / PKCS8 私钥
func (this Rsa) ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var parsedKey any
    if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
        if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
            return nil, err
        }
    }

    var pkey *rsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
        return nil, ErrNotRSAPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS1 带密码的私钥
func (this Rsa) ParseRSAPrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var parsedKey any

    var blockDecrypted []byte
    if blockDecrypted, err = x509.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    if parsedKey, err = x509.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
        if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
            return nil, err
        }
    }

    var pkey *rsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
        return nil, ErrNotRSAPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this Rsa) ParseRSAPKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var parsedKey any

    var blockDecrypted []byte
    if blockDecrypted, err = DecryptPKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
        return nil, err
    }

    if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *rsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
        return nil, ErrNotRSAPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS1 / PKCS8 公钥
func (this Rsa) ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
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

    var pkey *rsa.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
        return nil, ErrNotRSAPublicKey
    }

    return pkey, nil
}
