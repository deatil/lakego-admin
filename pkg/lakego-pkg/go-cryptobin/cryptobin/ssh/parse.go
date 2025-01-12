package ecgdsa

import (
    "errors"
    "crypto"
    "encoding/pem"

    crypto_ssh "golang.org/x/crypto/ssh"

    "github.com/deatil/go-cryptobin/ssh"
)

var (
    ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded Openssh key")
    ErrNotOpensshPublicKey = errors.New("key is not a valid SSH public key")
)

// 解析私钥
func (this SSH) ParseOpensshPrivateKeyFromPEM(key []byte) (crypto.PrivateKey, string, error) {
    // Parse PEM block
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, "", ErrKeyMustBePEMEncoded
    }

    return ssh.ParseOpenSSHPrivateKey(block.Bytes)
}

// 解析带密码的私钥
func (this SSH) ParseOpensshPrivateKeyFromPEMWithPassword(key []byte, password []byte) (crypto.PrivateKey, string, error) {
    var block *pem.Block
    if block, _ = pem.Decode(key); block == nil {
        return nil, "", ErrKeyMustBePEMEncoded
    }

    return ssh.ParseOpenSSHPrivateKeyWithPassword(block.Bytes, password)
}

// 解析公钥
func (this SSH) ParseOpensshPublicKeyFromPEM(key []byte) (crypto.PublicKey, string, error) {
    var err error

    // Parse the key
    var parsedKey crypto_ssh.PublicKey
    var comment string
    if parsedKey, comment, _, _, err = ssh.ParseAuthorizedKey(key); err != nil {
        return nil, "", err
    }

    var pkey crypto_ssh.CryptoPublicKey
    var ok bool

    if pkey, ok = parsedKey.(crypto_ssh.CryptoPublicKey); !ok {
        return nil, "", ErrNotOpensshPublicKey
    }

    return pkey.CryptoPublicKey(), comment, nil
}
