package ssh

import (
    "math/big"
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/pkg/errors"
    "golang.org/x/crypto/ssh"
)

// ecdsa
type KeyEcdsa struct {}

// 包装
func (this KeyEcdsa) Marshal(key crypto.PrivateKey, comment string) (string, []byte, []byte, error) {
    k, ok := key.(*ecdsa.PrivateKey)
    if !ok {
        return "", nil, nil, errors.Errorf("unsupported key type %T", key)
    }

    var curve, keyType string
    switch k.Curve.Params().Name {
        case "P-256":
            curve = "nistp256"
            keyType = ssh.KeyAlgoECDSA256
        case "P-384":
            curve = "nistp384"
            keyType = ssh.KeyAlgoECDSA384
        case "P-521":
            curve = "nistp521"
            keyType = ssh.KeyAlgoECDSA521
        default:
            return "", nil, nil, errors.Errorf("error serializing key: unsupported curve %s", k.Curve.Params().Name)
    }

    pub := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)

    // Marshal public key.
    pubKey := struct {
        KeyType string
        Curve   string
        Pub     []byte
    }{
        keyType, curve, pub,
    }
    pubkey := ssh.Marshal(pubKey)

    // Marshal private key.
    prikey := struct {
        Curve   string
        Pub     []byte
        D       *big.Int
        Comment string
    }{
        curve, pub, k.D,
        comment,
    }
    rest := ssh.Marshal(prikey)

    return keyType, pubkey, rest, nil
}

// 解析
func (this KeyEcdsa) Parse(rest []byte) (crypto.PrivateKey, string, error) {
    key := struct {
        Curve   string
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

    var curve elliptic.Curve
    switch key.Curve {
        case "nistp256":
            curve = elliptic.P256()
        case "nistp384":
            curve = elliptic.P384()
        case "nistp521":
            curve = elliptic.P521()
        default:
            return nil, "", errors.Errorf("error decoding key: unsupported elliptic curve %s", key.Curve)
    }

    N := curve.Params().N

    X, Y := elliptic.Unmarshal(curve, key.Pub)
    if X == nil || Y == nil {
        return nil, "", errors.New("error decoding key: failed to unmarshal public key")
    }

    if key.D.Cmp(N) >= 0 {
        return nil, "", errors.New("error decoding key: scalar is out of range")
    }

    x, y := curve.ScalarBaseMult(key.D.Bytes())
    if x.Cmp(X) != 0 || y.Cmp(Y) != 0 {
        return nil, "", errors.New("error decoding key: public key does not match private key")
    }

    return &ecdsa.PrivateKey{
        PublicKey: ecdsa.PublicKey{
            Curve: curve,
            X:     X,
            Y:     Y,
        },
        D: key.D,
    }, key.Comment, nil
}
