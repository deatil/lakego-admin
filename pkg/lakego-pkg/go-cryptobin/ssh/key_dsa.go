package ssh

import (
    "fmt"
    "errors"
    "math/big"
    "crypto"
    "crypto/dsa"

    "golang.org/x/crypto/ssh"
)

// DSA key
type KeyDSA struct {}

// Marshal key
func (this KeyDSA) Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error) {
    k, ok := key.(*dsa.PrivateKey)
    if !ok {
        return "", nil, nil, errors.New(fmt.Sprintf("unsupported key type %T", key))
    }

    keyType := ssh.KeyAlgoDSA

    pubKey := struct {
        KeyType string
        P, Q, G *big.Int
        Y       *big.Int
    }{
        keyType,
        k.PublicKey.P,
        k.PublicKey.Q,
        k.PublicKey.G,
        k.PublicKey.Y,
    }
    pubkey := ssh.Marshal(pubKey)

    // Marshal private key.
    prikey := struct {
        P, Q, G *big.Int
        Y       *big.Int
        X       *big.Int
        Comment string
    }{
        k.PublicKey.P,
        k.PublicKey.Q,
        k.PublicKey.G,
        k.PublicKey.Y,
        k.X,
        comment,
    }
    rest := ssh.Marshal(prikey)

    return keyType, pubkey, rest, nil
}

// Parse key
func (this KeyDSA) Parse(rest []byte) (crypto.PrivateKey, string, error) {
    // https://github.com/openssh/openssh-portable/blob/master/sshkey.c
    key := struct {
        P, Q, G *big.Int
        Y       *big.Int
        X       *big.Int
        Comment string
        Pad     []byte `ssh:"rest"`
    }{}

    if err := ssh.Unmarshal(rest, &key); err != nil {
        return nil, "", err
    }

    if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
        return nil, "", err
    }

    pk := &dsa.PrivateKey{
        PublicKey: dsa.PublicKey{
            Parameters: dsa.Parameters{
                P: key.P,
                Q: key.Q,
                G: key.G,
            },
            Y: key.Y,
        },
        X: key.X,
    }

    return pk, key.Comment, nil
}
