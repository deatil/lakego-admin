package ssh

import (
    "crypto"
    "crypto/ed25519"

    "github.com/pkg/errors"
    "golang.org/x/crypto/ssh"
)

// EdDsa
type KeyEdDsa struct {}

// 包装
func (this KeyEdDsa) Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error) {
    k, ok := key.(ed25519.PrivateKey)
    if !ok {
        return "", nil, nil, errors.Errorf("unsupported key type %T", key)
    }

    keyType := ssh.KeyAlgoED25519

    pub := make([]byte, ed25519.PublicKeySize)
    priv := make([]byte, ed25519.PrivateKeySize)
    copy(pub, k[ed25519.PublicKeySize:])
    copy(priv, k)

    // Marshal public key.
    pubKey := struct {
        KeyType string
        Pub     []byte
    }{
        keyType,
        pub,
    }
    pubkey := ssh.Marshal(pubKey)

    // Marshal private key.
    prikey := struct {
        Pub     []byte
        Priv    []byte
        Comment string
    }{
        pub, priv,
        comment,
    }
    rest := ssh.Marshal(prikey)

    return keyType, pubkey, rest, nil
}

// 解析
func (this KeyEdDsa) Parse(rest []byte) (crypto.PrivateKey, string, error) {
    key := struct {
        Pub     []byte
        Priv    []byte
        Comment string
        Pad     []byte `ssh:"rest"`
    }{}

    if err := ssh.Unmarshal(rest, &key); err != nil {
        return nil, "", err
    }

    if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
        return nil, "", err
    }

    if len(key.Priv) != ed25519.PrivateKeySize {
        return nil, "", errors.New("private key unexpected length")
    }

    pk := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
    copy(pk, key.Priv)

    return pk, key.Comment, nil
}
