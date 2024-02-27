package elgamal

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs1"
    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/elgamal"
)

var (
    ErrKeyMustBePEMEncoded  = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
    ErrNotEIGamalPrivateKey = errors.New("key is not a valid EIGamal private key")
    ErrNotEIGamalPublicKey  = errors.New("key is not a valid EIGamal public key")
)

// 解析私钥
func (this EIGamal) ParsePKCS1PrivateKeyFromPEM(key []byte) (*elgamal.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = elgamal.ParsePKCS1PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *elgamal.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*elgamal.PrivateKey); !ok {
        return nil, ErrNotEIGamalPrivateKey
    }

    return pkey, nil
}

// 解析私钥带密码
func (this EIGamal) ParsePKCS1PrivateKeyFromPEMWithPassword(key []byte, password string) (*elgamal.PrivateKey, error) {
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
    var parsedKey any
    if parsedKey, err = elgamal.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *elgamal.PrivateKey
    var ok bool
    if pkey, ok = parsedKey.(*elgamal.PrivateKey); !ok {
        return nil, ErrNotEIGamalPrivateKey
    }

    return pkey, nil
}

// 解析公钥
func (this EIGamal) ParsePKCS1PublicKeyFromPEM(key []byte) (*elgamal.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = elgamal.ParsePKCS1PublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *elgamal.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*elgamal.PublicKey); !ok {
        return nil, ErrNotEIGamalPublicKey
    }

    return pkey, nil
}

// =============


// 解析私钥 PKCS8
func (this EIGamal) ParsePKCS8PrivateKeyFromPEM(key []byte) (*elgamal.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = elgamal.ParsePKCS8PrivateKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *elgamal.PrivateKey
    var ok bool

    if pkey, ok = parsedKey.(*elgamal.PrivateKey); !ok {
        return nil, ErrNotEIGamalPrivateKey
    }

    return pkey, nil
}

// 解析 PKCS8 带密码的私钥
func (this EIGamal) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*elgamal.PrivateKey, error) {
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

    var parsedKey any
    if parsedKey, err = elgamal.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    var pkey *elgamal.PrivateKey
    var ok bool

    if pkey, ok = parsedKey.(*elgamal.PrivateKey); !ok {
        return nil, ErrNotEIGamalPrivateKey
    }

    return pkey, nil
}

// 解析公钥 PKCS8
func (this EIGamal) ParsePKCS8PublicKeyFromPEM(key []byte) (*elgamal.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    // Parse the key
    var parsedKey any
    if parsedKey, err = elgamal.ParsePKCS8PublicKey(block.Bytes); err != nil {
        return nil, err
    }

    var pkey *elgamal.PublicKey
    var ok bool

    if pkey, ok = parsedKey.(*elgamal.PublicKey); !ok {
        return nil, ErrNotEIGamalPublicKey
    }

    return pkey, nil
}

// ============

// 解析 xml 私钥
func (this EIGamal) ParsePrivateKeyFromXML(key []byte) (*elgamal.PrivateKey, error) {
    return elgamal.ParseXMLPrivateKey(key)
}

// 解析 xml 公钥
func (this EIGamal) ParsePublicKeyFromXML(key []byte) (*elgamal.PublicKey, error) {
    return elgamal.ParseXMLPublicKey(key)
}
