package rsa

import (
    "errors"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "golang.org/x/crypto/pkcs12"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotRSAPrivateKey    = errors.New("key is not a valid RSA private key")
    ErrNotRSAPublicKey     = errors.New("key is not a valid RSA public key")
)

// 解析 PKCS1 / PKCS8 私钥
func (this Rsa) ParsePrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
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
func (this Rsa) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
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
func (this Rsa) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
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

    var pkey *rsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
        return nil, ErrNotRSAPrivateKey
    }

    return pkey, nil
}

// 解析 pkf 证书
func (this Rsa) ParsePKCS12CertFromPEMWithPassword(pfxData []byte, password string) (*rsa.PrivateKey, error) {
    privateKey, _, err := pkcs12.Decode(pfxData, password)
    if err != nil {
        return nil, err
    }

    pkey, ok := privateKey.(*rsa.PrivateKey)
    if !ok {
        return nil, ErrNotRSAPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS1 公钥
func (this Rsa) ParsePKCS1PublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *rsa.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
        return nil, ErrNotRSAPublicKey
    }

    return pkey, nil
}

// 解析 PKCS8 公钥
func (this Rsa) ParsePKCS8PublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
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
