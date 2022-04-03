package cryptobin

import (
    "errors"
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/pem"
)

var (
    ErrNotECPublicKey  = errors.New("key is not a valid ECDSA public key")
    ErrNotECPrivateKey = errors.New("key is not a valid ECDSA private key")
)

// 解析私钥
func (this Ecdsa) ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey interface{}
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

// 解析公钥
func (this Ecdsa) ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey interface{}
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
