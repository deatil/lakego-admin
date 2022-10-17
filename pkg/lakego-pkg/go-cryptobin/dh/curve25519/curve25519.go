package curve25519

import (
    "io"
    "errors"
    "crypto"
    cryptorand "crypto/rand"

    "golang.org/x/crypto/curve25519"
)

// 公钥
type PublicKey struct {
    Y []byte
}

// 检测
func (this *PublicKey) Check() (err error) {
    if len(this.Y) != 32 {
        err = errors.New("peers public key is not 32 byte")
    }

    return
}

// 私钥
type PrivateKey struct {
    PublicKey

    X []byte
}

func (this *PrivateKey) Public() crypto.PublicKey {
    return &this.PublicKey
}

// 生成密码
func (this *PrivateKey) ComputeSecret(peersPublic *PublicKey) (secret []byte) {
    return ComputeSecret(this, peersPublic)
}

// 生成密钥对
func GenerateKey(rand io.Reader) (*PrivateKey, *PublicKey, error) {
    if rand == nil {
        rand = cryptorand.Reader
    }

    var err error
    var pri, pub [32]byte
    _, err = io.ReadFull(rand, pri[:])
    if err != nil {
        return nil, nil, err
    }

    pri[0] &= 248
    pri[31] &= 127
    pri[31] |= 64

    curve25519.ScalarBaseMult(&pub, &pri)

    public := &PublicKey{
        Y: pub[:],
    }

    private := &PrivateKey{
        X: pri[:],
        PublicKey: *public,
    }

    return private, public, nil
}

// 从私钥获取公钥
func GeneratePublicKey(private *PrivateKey) (*PublicKey, error) {
    var pri, pub [32]byte
    copy(pri[:], private.X)

    curve25519.ScalarBaseMult(&pub, &pri)

    public := &PublicKey{
        Y: pub[:],
    }

    return public, nil
}

// 生成密码
func ComputeSecret(private *PrivateKey, peersPublic *PublicKey) (secret []byte) {
    if len(private.X) != 32 {
        panic("ecdh: private key is not 32 byte")
    }

    if len(peersPublic.Y) != 32 {
        panic("ecdh: peers public key is not 32 byte")
    }

    var sec, pri, pub [32]byte
    copy(pri[:], private.X)
    copy(pub[:], peersPublic.Y)

    curve25519.ScalarMult(&sec, &pri, &pub)

    secret = sec[:]
    return
}
