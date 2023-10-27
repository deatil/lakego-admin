package sm2

import (
    "errors"
    "encoding/pem"
    crypto_x509 "crypto/x509"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"

    cryptobin_sm2 "github.com/deatil/go-cryptobin/sm2"
    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotECPrivateKey     = errors.New("key is not a valid SM2 private key")
)

// 解析私钥，默认为 PKCS8
func (this SM2) ParsePrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, nil)
}

// 解析私钥带密码，默认为 PKCS8
func (this SM2) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, []byte(password))
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
    var parsedKey any
    if parsedKey, err = cryptobin_sm2.ParseSM2PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *sm2.PrivateKey
    var ok bool

    if pkey, ok = parsedKey.(*sm2.PrivateKey); !ok {
        return nil, ErrNotECPrivateKey
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
    if blockDecrypted, err = crypto_x509.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = cryptobin_sm2.ParseSM2PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *sm2.PrivateKey
    var ok bool

    if pkey, ok = parsedKey.(*sm2.PrivateKey); !ok {
        return nil, ErrNotECPrivateKey
    }

    return pkey, nil
}

// ==========

// 解析 PKCS8 私钥
func (this SM2) ParsePKCS8PrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, nil)
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
    if blockDecrypted, err = cryptobin_pkcs8.DecryptPEMBlock(block, []byte(password)); err != nil {
        return nil, err
    }

    var pkey *sm2.PrivateKey
    if pkey, err = x509.ParsePKCS8UnecryptedPrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}

// ==========

// 解析公钥
func (this SM2) ParsePublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    return x509.ReadPublicKeyFromPem(key)
}
