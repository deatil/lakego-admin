package dh

import (
    "io"
    "errors"
    "crypto"
    "math/big"
    crypto_rand "crypto/rand"
)

var zero *big.Int = big.NewInt(0)
var one  *big.Int = big.NewInt(1)
var two  *big.Int = big.NewInt(2)

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

// 生成证书
func GenerateKey(param Parameters, rand io.Reader) (*PrivateKey, *PublicKey, error) {
    if param.P == nil {
        err := errors.New("crypto/dh: prime is nil")
        return nil, nil, err
    }
    if param.G == nil {
        err := errors.New("crypto/dh: generator is nil")
        return nil, nil, err
    }

    if rand == nil {
        rand = crypto_rand.Reader
    }

    min := big.NewInt(int64(param.P.BitLen() + 1))
    bytes := make([]byte, (param.P.BitLen()+7)/8)

    private := &PrivateKey{}
    private.PublicKey.Parameters = param

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

// 生成密钥
func ComputeSecret(private *PrivateKey, peersPublic *PublicKey) *big.Int {
    secret := new(big.Int).Exp(peersPublic.Y, private.X, private.P)

    return secret
}

func IsSafePrimeGroup(param Parameters, n int) bool {
    q := new(big.Int).Sub(param.P, one)
    q = q.Div(q, two)

    return q.ProbablyPrime(n)
}

// DH groups defined in https://www.ietf.org/rfc/rfc3526.txt
const (
    // The 2048 bit prime form 3.
    rfc3526_2048G = "02"
    rfc3526_2048P = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3" +
        "404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BF" +
        "B5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C6" +
        "2F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28" +
        "FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

    // The 3072 bit prime form 4.
    rfc3526_3072G = "02"
    rfc3526_3072P = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3" +
        "404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BF" +
        "B5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C6" +
        "2F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28" +
        "FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1" +
        "CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA0" +
        "6D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B8" +
        "2D120A93AD2CAFFFFFFFFFFFFFFFF"

    // The 4096 bit prime form 5.
    rfc3526_4096G = "02"
    rfc3526_4096P = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3" +
        "404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BF" +
        "B5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C6" +
        "2F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28" +
        "FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1" +
        "CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA0" +
        "6D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B8" +
        "2D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF" +
        "92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B" +
        "05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"

    // ==========

    // The 512 bit prime
    rfc3526_512G = "02"
    rfc3526_512P = "DAF00FD157678582D295554714D3FBE6B4CB639C31202B6040BB395D7C1326CAADCE1393B5C06BEB441227FD80E8397613181909B66564DC360D8557357971E3"

    // The 1024 bit prime
    rfc3526_1024G = "02"
    rfc3526_1024P = "E3C82FD592C82ABDD5A3AB4271E8298A16D7A77337C2205514B2016AFA6849325F736D876EB0A7B0B5C895CA526D8EF81F54850A05272B05DF75A2276938976586EFD45668028C97A2D974EEFFB52E0C5FFE8D7C81DC9285A77BAC30987E1BCB7FB21367D9C0DE6F8D339B9A161E15A96FB89D68BFE4B51E5D8B35ED11D5BF63"

    // The 2048 bit prime
    rfc3526_2048G2 = "02"
    rfc3526_2048P2 = "D646294E051E6B2AB3BA057F489DF6A58E1CE5D542B4436A19AE49AF2B08A73B08F0F3DD7B0F1B0839D8140561DFB3994A663AAA624F4DE9E8E2A9803588592841C5E5F1E11ADBCA75DF78F369A8F7598262794F144F49E7655C07702A951903CD2FA553100B05D41641A97541DA6D8253126B3A378718FB370C51F39D2F732CAFD07357A5C9B1E9C7CFA9CD82C49C920C157B4356C4FF9CF57C37122C9C0D4809A1FC17595073FE1574411B72DD37E57E2A41E8B868898206E9BD409FF74C065922DFB24E047D8FFFB11F56039044E281B60351FE6E518B9FAEA6E705A9949EE6BF8FAA053591C561C097165621D7017348910B78F3A298FCACF49C8C174853"
)

// described in RFC 3526 (3.). The prime is a 2048 bit value.
func P2048() Parameters {
    p, _ := new(big.Int).SetString(rfc3526_2048P, 16)
    g, _ := new(big.Int).SetString(rfc3526_2048G, 16)

    ret := Parameters{
        P: p,
        G: g,
    }
    return ret
}

// described in RFC 3526 (4.). The prime is a 3072 bit value.
func P3072() Parameters {
    p, _ := new(big.Int).SetString(rfc3526_3072P, 16)
    g, _ := new(big.Int).SetString(rfc3526_3072G, 16)

    ret := Parameters{
        P: p,
        G: g,
    }
    return ret
}

// described in RFC 3526 (5.). The prime is a 4096 bit value.
func P4096() Parameters {
    p, _ := new(big.Int).SetString(rfc3526_2048P, 16)
    g, _ := new(big.Int).SetString(rfc3526_2048G, 16)

    ret := Parameters{
        P: p,
        G: g,
    }

    return ret
}

// 512, 适配网络在线生成
func P512() Parameters {
    p, _ := new(big.Int).SetString(rfc3526_512P, 16)
    g, _ := new(big.Int).SetString(rfc3526_512G, 16)

    ret := Parameters{
        P: p,
        G: g,
    }
    return ret
}

// 1024, 适配网络在线生成
func P1024() Parameters {
    p, _ := new(big.Int).SetString(rfc3526_1024P, 16)
    g, _ := new(big.Int).SetString(rfc3526_1024G, 16)

    ret := Parameters{
        P: p,
        G: g,
    }
    return ret
}

// 2048, 适配网络在线生成
func P2048_2() Parameters {
    p, _ := new(big.Int).SetString(rfc3526_2048P2, 16)
    g, _ := new(big.Int).SetString(rfc3526_2048G2, 16)

    ret := Parameters{
        P: p,
        G: g,
    }
    return ret
}
