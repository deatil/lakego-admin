package dsa

import (
    "errors"
    "crypto/dsa"
    "crypto/x509"
    "encoding/pem"

    cryptobin_dsa "github.com/deatil/go-cryptobin/dsa"
    cryptobin_pkcs1 "github.com/deatil/go-cryptobin/pkcs1"
    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotDSAPrivateKey    = errors.New("key is not a valid DSA private key")
    ErrNotDSAPublicKey     = errors.New("key is not a valid DSA public key")
)

// 解析私钥
func (this DSA) ParsePKCS1PrivateKeyFromPEM(key []byte) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS1PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *dsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*dsa.PrivateKey); !ok {
        return nil, ErrNotDSAPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this DSA) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = cryptobin_pkcs1.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *dsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*dsa.PrivateKey); !ok {
        return nil, ErrNotDSAPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this DSA) ParsePKCS1PublicKeyFromPEM(key []byte) (*dsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS1PublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *dsa.PublicKey
    var ok bool
    if pkey, ok = parsedKey.(*dsa.PublicKey); !ok {
        return nil, ErrNotDSAPublicKey
    }

    return pkey, nil
}

// =============


// 解析私钥 PKCS8
func (this DSA) ParsePKCS8PrivateKeyFromPEM(key []byte) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS8PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *dsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*dsa.PrivateKey); !ok {
        return nil, ErrNotDSAPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this DSA) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*dsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var blockDecrypted []byte
    if blockDecrypted, err = cryptobin_pkcs8.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *dsa.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*dsa.PrivateKey); !ok {
        return nil, ErrNotDSAPrivateKey
    }

    return pkey, nil
}

// 解析公钥 PKCS8
func (this DSA) ParsePKCS8PublicKeyFromPEM(key []byte) (*dsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_dsa.ParsePKCS8PublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *dsa.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*dsa.PublicKey); !ok {
        return nil, ErrNotDSAPublicKey
    }

    return pkey, nil
}

// ============

// 解析 xml 私钥
func (this DSA) ParsePrivateKeyFromXML(key []byte) (*dsa.PrivateKey, error) {
    return cryptobin_dsa.ParseXMLPrivateKey(key)
}

// 解析 xml 公钥
func (this DSA) ParsePublicKeyFromXML(key []byte) (*dsa.PublicKey, error) {
    return cryptobin_dsa.ParseXMLPublicKey(key)
}
