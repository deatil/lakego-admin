package ssh

import (
    "math/big"
    "crypto"
    "crypto/rsa"

    "github.com/pkg/errors"
    "golang.org/x/crypto/ssh"
)

// rsa
type KeyRsa struct {}

// 包装
func (this KeyRsa) Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error) {
    k, ok := key.(*rsa.PrivateKey)
    if !ok {
        return "", nil, nil, errors.Errorf("unsupported key type %T", key)
    }

    keyType := ssh.KeyAlgoRSA

    E := new(big.Int).SetInt64(int64(k.PublicKey.E))

    pubKey := struct {
        KeyType string
        E       *big.Int
        N       *big.Int
    }{
        keyType,
        E,
        k.PublicKey.N,
    }
    pubkey := ssh.Marshal(pubKey)

    // Marshal private key.
    prikey := struct {
        N       *big.Int
        E       *big.Int
        D       *big.Int
        Iqmp    *big.Int
        P       *big.Int
        Q       *big.Int
        Comment string
    }{
        k.PublicKey.N, E,
        k.D, k.Precomputed.Qinv, k.Primes[0], k.Primes[1],
        comment,
    }
    rest := ssh.Marshal(prikey)

    return keyType, pubkey, rest, nil
}

// 包装
func (this KeyRsa) Parse(rest []byte) (crypto.PrivateKey, error) {
    // https://github.com/openssh/openssh-portable/blob/master/sshkey.c
    key := struct {
        N       *big.Int
        E       *big.Int
        D       *big.Int
        Iqmp    *big.Int
        P       *big.Int
        Q       *big.Int
        Comment string
        Pad     []byte `ssh:"rest"`
    }{}

    if err := ssh.Unmarshal(rest, &key); err != nil {
        return nil, err
    }

    for i, b := range key.Pad {
        if int(b) != i+1 {
            return nil, errors.New("error decoding key: padding not as expected")
        }
    }

    pk := &rsa.PrivateKey{
        PublicKey: rsa.PublicKey{
            N: key.N,
            E: int(key.E.Int64()),
        },
        D:      key.D,
        Primes: []*big.Int{key.P, key.Q},
    }

    if err := pk.Validate(); err != nil {
        return nil, err
    }

    pk.Precompute()

    return pk, nil
}
