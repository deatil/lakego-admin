package dh

import (
    "io"
    "errors"
    "crypto"
    "math/big"
)

var zero *big.Int = big.NewInt(0)
var one  *big.Int = big.NewInt(1)
var two  *big.Int = big.NewInt(2)

// 分组 id
type GroupID uint

const (
    P1001 GroupID = 1 + iota
    P1002
    P1536
    P2048
    P3072
    P4096
    P6144
    P8192
)

// 公用参数
type Parameters struct {
    // The prime
    P *big.Int

    // The generator
    G *big.Int
}

// 公钥
type PublicKey struct {
    Parameters

    // 公钥
    Y *big.Int
}

// 检测
// public key is < 0 or > g.P.
func (this *PublicKey) Check() (err error) {
    if !((*this.Y).Cmp(zero) >= 0 && (*this.Y).Cmp(this.P) == -1) {
        err = errors.New("peer's public is not a possible group element")
    }

    return
}

// 私钥
type PrivateKey struct {
    PublicKey

    // 私钥
    X *big.Int
}

func (this *PrivateKey) Public() crypto.PublicKey {
    return &this.PublicKey
}

// 生成密钥
func (this *PrivateKey) ComputeSecret(peersPublic *PublicKey) (secret []byte) {
    return ComputeSecret(this, peersPublic)
}

// 生成证书
func GenerateKey(groupID GroupID, rand io.Reader) (*PrivateKey, *PublicKey, error) {
    param, err := GetMODGroup(groupID)
    if err != nil {
        return nil, nil, err
    }

    return GenerateKeyWithGroup(param, rand)
}

// 生成证书
func GenerateKeyWithGroup(param *Group, rand io.Reader) (*PrivateKey, *PublicKey, error) {
    if param.P == nil {
        err := errors.New("crypto/dh: prime is nil")
        return nil, nil, err
    }
    if param.G == nil {
        err := errors.New("crypto/dh: generator is nil")
        return nil, nil, err
    }

    min := big.NewInt(int64(param.P.BitLen() + 1))
    bytes := make([]byte, (param.P.BitLen()+7)/8)

    private := &PrivateKey{}
    private.PublicKey.Parameters = Parameters{
        P: param.P,
        G: param.G,
    }

    for private.X == nil {
        _, err := io.ReadFull(rand, bytes)
        if err != nil {
            private.X = nil
            return nil, nil, errors.New("private x is nil")
        }

        // Clear bits in the first byte to increase
        // the probability that the candidate is < g.P.
        bytes[0] = 0
        if private.X == nil {
            private.X = new(big.Int)
        }

        (*private.X).SetBytes(bytes)
        if (*private.X).Cmp(min) < 0 {
            private.X = nil
        }
    }

    private.PublicKey.Y = new(big.Int).Exp(param.G, private.X, param.P)

    public := &private.PublicKey

    return private, public, nil
}

// 从私钥获取公钥
func GeneratePublicKey(private *PrivateKey) (*PublicKey, error) {
    pub := new(big.Int).Exp(private.G, private.X, private.P)

    public := &PublicKey{
        Y: pub,
        Parameters: Parameters{
            P: private.P,
            G: private.G,
        },
    }

    return public, nil
}

// 生成密钥
func ComputeSecret(private *PrivateKey, peersPublic *PublicKey) []byte {
    secret := new(big.Int).Exp(peersPublic.Y, private.X, private.P)

    return secret.Bytes()
}

// 判断是否为安全数据
func IsSafePrimeParameters(param Parameters, n int) bool {
    q := new(big.Int).Sub(param.P, one)
    q = q.Div(q, two)

    return q.ProbablyPrime(n)
}
