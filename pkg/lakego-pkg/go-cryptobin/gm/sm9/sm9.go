package sm9

import (
    "io"
    "math"
    "math/big"
    "crypto/rand"
    "encoding/binary"

    "github.com/pkg/errors"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/gm/sm9/sm9curve"
)

type hashMode int

const (
    // hashmode used in h1: 0x01
    H1 hashMode = iota + 1
    // hashmode used in h2: 0x02
    H2
)

// G2Bytes = G2.Marshal()
type MasterPubKey struct {
    Mpk *sm9curve.G2
}

// MasterKey contains a master secret key and a master public key.
type MasterKey struct {
    MasterPubKey
    D *big.Int
}

// UserKey contains a secret key.
// G1Bytes = G1.Marshal()
type UserKey struct {
    Sk *sm9curve.G1
}

// Sm9Sig contains a big number and an element in G1.
type Sm9Sig struct {
    H *big.Int
    S *sm9curve.G1
}

// hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func hash(z []byte, n *big.Int, h hashMode) *big.Int {
    // counter
    ct := 1

    hlen := 8 * int(math.Ceil(float64(5*n.BitLen()/32)))
    count := int(math.Ceil(float64(hlen/256)))

    var ha []byte
    for i := 0; i < count; i++ {
        msg := append([]byte{byte(h)}, z...)
        buf := make([]byte, 4)

        binary.BigEndian.PutUint32(buf, uint32(ct))
        msg = append(msg, buf...)
        hai := sm3.Sum(msg)
        ct++

        if float64(hlen)/256 == float64(int64(hlen/256)) && i == int(math.Ceil(float64(hlen/256)))-1 {
            ha = append(ha, hai[:(hlen-256*int(math.Floor(float64(hlen/256))))/32]...)
        } else {
            ha = append(ha, hai[:]...)
        }
    }

    bn := new(big.Int).SetBytes(ha)
    one := big.NewInt(1)

    nMinus1 := new(big.Int).Sub(n, one)

    bn.Mod(bn, nMinus1)
    bn.Add(bn, one)

    return bn
}

// generate rand numbers in [1,n-1].
func randFieldElement(rand io.Reader, n *big.Int) (k *big.Int, err error) {
    one := big.NewInt(1)
    b := make([]byte, 256/8+8)

    _, err = io.ReadFull(rand, b)
    if err != nil {
        return
    }

    k = new(big.Int).SetBytes(b)
    nMinus1 := new(big.Int).Sub(n, one)
    k.Mod(k, nMinus1)

    return
}

// generate master key for KGC(Key Generate Center).
func MasterKeyGen(rand io.Reader) (mk *MasterKey, err error) {
    s, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, errors.Errorf("gen rand num err:%s", err)
    }

    mk = new(MasterKey)
    mk.D = new(big.Int).Set(s)

    mk.Mpk = new(sm9curve.G2).ScalarBaseMult(s)

    return
}

// generate user's secret key.
func UserKeyGen(mk *MasterKey, id []byte, hid byte) (uk *UserKey, err error) {
    id = append(id, hid)
    n := sm9curve.Order

    t1 := hash(id, n, H1)
    t1.Add(t1, mk.D)

    // if t1 = 0, we need to regenerate the master key.
    if t1.BitLen() == 0 || t1.Cmp(n) == 0 {
        return nil, errors.New("need to regen mk!")
    }

    t1.ModInverse(t1, n)

    // t2 = s*t1^-1
    t2 := new(big.Int).Mul(mk.D, t1)

    uk = new(UserKey)
    uk.Sk = new(sm9curve.G1).ScalarBaseMult(t2)

    return
}

// sm9 sign algorithm:
// A1:compute g = e(P1,Ppub);
// A2:choose random num r in [1,n-1];
// A3:compute w = g^r;
// A4:compute h = H2(M||w,n);
// A5:compute l = (r-h) mod n, if l = 0 goto A2;
// A6:compute S = l·sk.
func Sign(uk *UserKey, mpk *MasterPubKey, msg []byte) (sig *Sm9Sig, err error) {
    sig = new(Sm9Sig)
    n := sm9curve.Order
    g := sm9curve.Pair(sm9curve.Gen1, mpk.Mpk)

regen:
    r, err := randFieldElement(rand.Reader, n)
    if err != nil {
        return nil, errors.Errorf("gen rand num failed:%s", err)
    }

    w := new(sm9curve.GT).ScalarMult(g, r)
    wBytes := w.Marshal()

    msg = append(msg, wBytes...)
    h := hash(msg, n, H2)

    sig.H = new(big.Int).Set(h)

    l := new(big.Int).Sub(r, h)
    l.Mod(l, n)

    if l.BitLen() == 0 {
        goto regen
    }

    sig.S = new(sm9curve.G1).ScalarMult(uk.Sk, l)

    return
}

// sm9 verify algorithm(given sig (h',S'), message M' and user's id):
// B1:compute g = e(P1,Ppub);
// B2:compute t = g^h';
// B3:compute h1 = H1(id||hid,n);
// B4:compute P = h1·P2+Ppub;
// B5:compute u = e(S',P);
// B6:compute w' = u·t;
// B7:compute h2 = H2(M'||w',n), check if h2 = h'.
func Verify(mpk *MasterPubKey, sig *Sm9Sig, msg []byte, id []byte, hid byte) bool {
    n := sm9curve.Order
    g := sm9curve.Pair(sm9curve.Gen1, mpk.Mpk)

    t := new(sm9curve.GT).ScalarMult(g, sig.H)

    id = append(id, hid)
    h1 := hash(id, n, H1)

    P := new(sm9curve.G2).ScalarBaseMult(h1)
    P.Add(P, mpk.Mpk)

    u := sm9curve.Pair(sig.S, P)
    w := new(sm9curve.GT).Add(u, t)

    wBytes := w.Marshal()
    msg = append(msg, wBytes...)

    h2 := hash(msg, n, H2)
    if h2.Cmp(sig.H) != 0 {
        return false
    }

    return true
}
