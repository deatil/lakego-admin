package sm2

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/pkcs8"
    "github.com/deatil/go-cryptobin/gm/sm2"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
)

// 解析 SM2 PKCS8 私钥
func ParseSM2PrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
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

// 解析 SM2 PKCS8 私钥带密码
func ParseSM2PrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
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

// 解析 SM2 PKCS8 公钥
func ParseSM2PublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var pkey *sm2.PublicKey
    if pkey, err = sm2.ParsePublicKey(block.Bytes); err != nil {
        return nil, err
    }

    return pkey, nil
}
