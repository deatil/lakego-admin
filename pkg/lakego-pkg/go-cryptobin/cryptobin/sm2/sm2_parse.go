package sm2

import (
    "errors"
    "encoding/pem"

    "github.com/tjfoc/gmsm/sm2"
    "github.com/tjfoc/gmsm/x509"

    cryptobin_pkcs8 "github.com/deatil/go-cryptobin/pkcs8"
    cryptobin_pkcs8pbe "github.com/deatil/go-cryptobin/pkcs8pbe"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
)

// 解析 SM2 PKCS8 私钥
func (this SM2) ParsePrivateKeyFromPEM(key []byte) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, nil)
}

// 解析 SM2 PKCS8 私钥带密码
func (this SM2) ParsePrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
    return x509.ReadPrivateKeyFromPem(key, []byte(password))
}

// 解析 PSM2 KCS8 带密码的私钥
func (this SM2) ParsePKCS8PrivateKeyFromPEMWithPassword(key []byte, password string) (*sm2.PrivateKey, error) {
    var err error

    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, ErrKeyMustBePEMEncoded
    }

    var pkey *sm2.PrivateKey

    var blockDecrypted []byte
    if blockDecrypted, err = cryptobin_pkcs8.DecryptPKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
        if blockDecrypted, err = cryptobin_pkcs8pbe.DecryptPKCS8PrivateKey(block.Bytes, []byte(password)); err != nil {
            return nil, err
        }
    }

    if pkey, err = x509.ParsePKCS8UnecryptedPrivateKey(blockDecrypted); err != nil {
        return nil, err
    }

    return pkey, nil
}


// 解析 SM2 PKCS8 公钥
func (this SM2) ParsePublicKeyFromPEM(key []byte) (*sm2.PublicKey, error) {
    return x509.ReadPublicKeyFromPem(key)
}
