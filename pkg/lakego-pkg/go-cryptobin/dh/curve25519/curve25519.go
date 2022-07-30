package curve25519

import (
    "io"
    "errors"
    cryptorand "crypto/rand"

    "golang.org/x/crypto/curve25519"
)

// 公钥
type PublicKey []byte

// 私钥
type PrivateKey []byte

// Ecdh25519
type Ecdh25519 struct{}

// 生成密钥对
func (this Ecdh25519) GenerateKey(rand io.Reader) (private PrivateKey, public PublicKey, err error) {
    if rand == nil {
        rand = cryptorand.Reader
    }

    var pri, pub [32]byte
    _, err = io.ReadFull(rand, pri[:])
    if err != nil {
        return
    }

    pri[0] &= 248
    pri[31] &= 127
    pri[31] |= 64

    curve25519.ScalarBaseMult(&pub, &pri)

    private = pri[:]
    public = pub[:]
    return
}

// 生成公钥
func (this Ecdh25519) PublicKey(private PrivateKey) (public PublicKey) {
    if len(private) != 32 {
        panic("ecdh: private key is not 32 byte")
    }

    var pri, pub [32]byte
    copy(pri[:], private)

    curve25519.ScalarBaseMult(&pub, &pri)

    public = pub[:]
    return
}

// 检测
func (this Ecdh25519) Check(peersPublic PublicKey) (err error) {
    if len(peersPublic) != 32 {
        err = errors.New("peers public key is not 32 byte")
    }
    return
}

// 生成密码
func (this Ecdh25519) ComputeSecret(private PrivateKey, peersPublic PublicKey) (secret []byte) {
    if len(private) != 32 {
        panic("ecdh: private key is not 32 byte")
    }

    if len(peersPublic) != 32 {
        panic("ecdh: peers public key is not 32 byte")
    }

    var sec, pri, pub [32]byte
    copy(pri[:], private)
    copy(pub[:], peersPublic)

    curve25519.ScalarMult(&sec, &pri, &pub)

    secret = sec[:]
    return
}

// 构造函数
func New() Ecdh25519 {
    return Ecdh25519{}
}
