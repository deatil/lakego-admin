package sm2

import (
    "errors"
    "crypto/x509"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("go-cryptobin/sm2: invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPrivateKey     = errors.New("go-cryptobin/sm2: key is not a valid SM2 private key")
)

// 解析私钥，默认为 PKCS8
func (this SM2) ParsePrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return this.ParsePKCS8PrivateKeyFromPEM(key)
}

// 解析私钥带密码，默认为 PKCS8
func (this SM2) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
    return this.ParsePKCS8PrivateKeyFromPEMWithPassword(key, password)
}

// ==========

// 解析 PKCS1 私钥
func (this SM2) ParsePKCS1PrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var pkey *sm2.PrivateKey
    if pkey, err = sm2.ParseSM2PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析 PKCS1 私钥带密码
func (this SM2) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
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
    var pkey *sm2.PrivateKey
    if pkey, err = sm2.ParseSM2PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析 PKCS8 私钥
func (this SM2) ParsePKCS8PrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var pkey *sm2.PrivateKey
    if pkey, err = sm2.ParsePrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this SM2) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
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

    var pkey *sm2.PrivateKey
    if pkey, err = sm2.ParsePrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析公钥
func (this SM2) ParsePublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = sm2.ParsePublicKey(block.Bytes); err != nil {
        if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
            parsedKey = cert.PublicKey
        } else {
            return nil, err
        }
    }

    var pkey *sm2.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*sm2.PublicKey); !ok {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}
