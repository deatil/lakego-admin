package ssh

import (
    "math/big"
    "crypto"
    "crypto/elliptic"

    "github.com/pkg/errors"
    "golang.org/x/crypto/ssh"

    "github.com/tjfoc/gmsm/sm2"
)

var (
    KeyAlgoSM2 = "ssh-sm2"
)

// SM2
type KeySM2 struct {}

// 包装
func (this KeySM2) Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error) {
    k, ok := key.(*sm2.PrivateKey)
    if !ok {
        return "", nil, nil, errors.Errorf("unsupported key type %T", key)
    }

    keyType := KeyAlgoSM2

    pub := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)

    // Marshal public key.
    pubKey := struct {
        KeyType string
        Pub     []byte
    }{
        keyType, pub,
    }
    pubkey := ssh.Marshal(pubKey)

    // Marshal private key.
    prikey := struct {
        Pub     []byte
        D       *big.Int
        Comment string
    }{
        pub, k.D,
        comment,
    }
    rest := ssh.Marshal(prikey)

    return keyType, pubkey, rest, nil
}

// 解析
func (this KeySM2) Parse(rest []byte) (crypto.PrivateKey, string, error) {
    key := struct {
        Pub     []byte
        D       *big.Int
        Comment string
        Pad     []byte `ssh:"rest"`
    }{}

    if err := ssh.Unmarshal(rest, &key); err != nil {
        return nil, "", errors.Wrap(err, "error unmarshaling key")
    }

    if err := checkOpenSSHKeyPadding(key.Pad); err != nil {
        return nil, "", err
    }

    curve := sm2.P256Sm2()

    X, Y := elliptic.Unmarshal(curve, key.Pub)
    if X == nil || Y == nil {
        return nil, "", errors.New("error decoding key: failed to unmarshal public key")
    }

    N := curve.Params().N

    if key.D.Cmp(N) >= 0 {
        return nil, "", errors.New("error decoding key: scalar is out of range")
    }

    x, y := curve.ScalarBaseMult(key.D.Bytes())
    if x.Cmp(X) != 0 || y.Cmp(Y) != 0 {
        return nil, "", errors.New("error decoding key: public key does not match private key")
    }

    return &sm2.PrivateKey{
        PublicKey: sm2.PublicKey{
            Curve: curve,
            X:     X,
            Y:     Y,
        },
        D: key.D,
    }, key.Comment, nil
}
