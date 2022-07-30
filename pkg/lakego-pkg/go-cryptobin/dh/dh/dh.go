package dh

import (
    "io"
    "errors"
    "math/big"
    cryptorand "crypto/rand"
)

var zero *big.Int = big.NewInt(0)
var one  *big.Int = big.NewInt(1)
var two  *big.Int = big.NewInt(2)

// 公钥
// bytes := big.Int.Bytes()
type PublicKey  *big.Int

// 私钥
type PrivateKey *big.Int

// dh
type DH struct {
    // The prime
    P *big.Int

    // The generator
    G *big.Int
}

// 生成证书
func (this *DH) GenerateKey(rand io.Reader) (private PrivateKey, public PublicKey, err error) {
    if this.P == nil {
        err = errors.New("group prime is nil")
        return
    }
    if this.G == nil {
        err = errors.New("crypto/dh: group generator is nil")
        return
    }

    if rand == nil {
        rand = cryptorand.Reader
    }

    min := big.NewInt(int64(this.P.BitLen() + 1))
    bytes := make([]byte, (this.P.BitLen()+7)/8)

    for private == nil {
        _, err = io.ReadFull(rand, bytes)
        if err != nil {
            private = nil
            return
        }

        // Clear bits in the first byte to increase
        // the probability that the candidate is < g.P.
        bytes[0] = 0
        if private == nil {
            private = new(big.Int)
        }

        (*private).SetBytes(bytes)
        if (*private).Cmp(min) < 0 {
            private = nil
        }
    }

    public = new(big.Int).Exp(this.G, private, this.P)
    return
}

// 生成公钥
func (this *DH) PublicKey(private PrivateKey) (public PublicKey) {
    public = new(big.Int).Exp(this.G, private, this.P)
    return
}

// 检测
// public key is < 0 or > g.P.
func (this *DH) Check(peersPublic PublicKey) (err error) {
    if !((*peersPublic).Cmp(zero) >= 0 && (*peersPublic).Cmp(this.P) == -1) {
        err = errors.New("peer's public is not a possible group element")
    }

    return
}

// 生成密钥
func (this *DH) ComputeSecret(private PrivateKey, peersPublic PublicKey) (secret *big.Int) {
    secret = new(big.Int).Exp(peersPublic, private, this.P)
    return
}

func IsSafePrimeGroup(dh *DH, n int) bool {
    q := new(big.Int).Sub(dh.P, one)
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
)

// described in RFC 3526 (3.). The prime is a 2048 bit value.
func NewDH3526_2048() *DH {
    p, _ := new(big.Int).SetString(rfc3526_2048P, 16)
    g, _ := new(big.Int).SetString(rfc3526_2048G, 16)

    ret := &DH{
        P: p,
        G: g,
    }
    return ret
}

// described in RFC 3526 (4.). The prime is a 3072 bit value.
func NewDH3526_3072() *DH {
    p, _ := new(big.Int).SetString(rfc3526_3072P, 16)
    g, _ := new(big.Int).SetString(rfc3526_3072G, 16)

    ret := &DH{
        P: p,
        G: g,
    }
    return ret
}

// described in RFC 3526 (5.). The prime is a 4096 bit value.
func NewDH3526_4096() *DH {
    p, _ := new(big.Int).SetString(rfc3526_2048P, 16)
    g, _ := new(big.Int).SetString(rfc3526_2048G, 16)

    ret := &DH{
        P: p,
        G: g,
    }

    return ret
}
