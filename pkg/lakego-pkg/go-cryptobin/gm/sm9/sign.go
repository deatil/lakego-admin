package sm9

import (
    "io"
    "crypto"
    "math/big"
    "encoding/asn1"

    "github.com/pkg/errors"

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
type SignMasterPublicKey struct {
    Mpk *sm9curve.G2
}

// Equal reports whether pub and x have the same value.
func (pub *SignMasterPublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*SignMasterPublicKey)
    if !ok {
        return false
    }

    return pub.Mpk.Equal(xx.Mpk)
}

// SignMasterPrivateKey contains a master secret key and a master public key.
type SignMasterPrivateKey struct {
    SignMasterPublicKey
    D *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *SignMasterPrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*SignMasterPrivateKey)
    if !ok {
        return false
    }

    return priv.SignMasterPublicKey.Equal(&xx.SignMasterPublicKey) &&
        bigIntEqual(priv.D, xx.D)
}

func (this *SignMasterPrivateKey) PublicKey() *SignMasterPublicKey {
    return &this.SignMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (this *SignMasterPrivateKey) Public() crypto.PublicKey {
    return this.PublicKey()
}

// SignPrivateKey contains a secret key.
// G1Bytes = G1.Marshal()
type SignPrivateKey struct {
    Sk *sm9curve.G1
    SignMasterPublicKey
}

// Equal reports whether priv and x have the same value.
func (priv *SignPrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*SignPrivateKey)
    if !ok {
        return false
    }

    return priv.Sk.Equal(xx.Sk)
}

func (this *SignPrivateKey) PublicKey() *SignMasterPublicKey {
    return &this.SignMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (this *SignPrivateKey) Public() crypto.PublicKey {
    return this.PublicKey()
}

// generate master key for KGC(Key Generate Center).
func GenerateSignMasterPrivateKey(rand io.Reader) (mk *SignMasterPrivateKey, err error) {
    s, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, errors.Errorf("gen rand num err:%s", err)
    }

    mk = new(SignMasterPrivateKey)
    mk.D = new(big.Int).Set(s)
    mk.Mpk = new(sm9curve.G2).ScalarBaseMult(s)

    return
}

// generate user's secret key.
func GenerateSignPrivateKey(mk *SignMasterPrivateKey, id []byte, hid byte) (uk *SignPrivateKey, err error) {
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

    uk = new(SignPrivateKey)
    uk.Sk = new(sm9curve.G1).ScalarBaseMult(t2)
    uk.Mpk = mk.Mpk

    return
}

func NewSignMasterPrivateKey(bytes []byte) (mke *SignMasterPrivateKey, err error) {
    mke = new(SignMasterPrivateKey)

    mke.D = new(big.Int).SetBytes(bytes)

    d := new(big.Int).SetBytes(sm9curve.NormalizeScalar(bytes))
    mke.Mpk = new(sm9curve.G2).ScalarBaseMult(d)

    return
}

// 输出明文
func ToSignMasterPrivateKey(mke *SignMasterPrivateKey) []byte {
    return mke.D.Bytes()
}

func NewSignMasterPublicKey(bytes []byte) (mbk *SignMasterPublicKey, err error) {
    g := new(sm9curve.G2)
    _, err = g.Unmarshal(bytes)
    if err != nil {
        return nil, err
    }

    mbk = new(SignMasterPublicKey)
    mbk.Mpk = g

    return
}

// 输出明文
func ToSignMasterPublicKey(pub *SignMasterPublicKey) []byte {
    return pub.Mpk.Marshal()
}

func NewSignPrivateKey(bytes []byte) (uke *SignPrivateKey, err error) {
    var pub []byte

    g1 := new(sm9curve.G1)
    pub, err = g1.Unmarshal(bytes)
    if err != nil {
        return nil, err
    }

    if len(pub) == 0 {
        return nil, errors.New("key need publickey bytes")
    }

    uke = new(SignPrivateKey)
    uke.Sk = g1

    g2 := new(sm9curve.G2)
    _, err = g2.Unmarshal(pub)
    if err != nil {
        return nil, err
    }

    uke.Mpk = g2

    return
}

// 输出明文
func ToSignPrivateKey(pri *SignPrivateKey) []byte {
    if pri.Mpk == nil {
        return nil
    }

    pub := pri.Mpk.Marshal()

    return append(pri.Sk.Marshal(), pub...)
}

// sm9 sign algorithm:
// A1:compute g = e(P1,Ppub);
// A2:choose random num r in [1,n-1];
// A3:compute w = g^r;
// A4:compute h = H2(M||w,n);
// A5:compute l = (r-h) mod n, if l = 0 goto A2;
// A6:compute S = l·sk.
func Sign(rand io.Reader, pri *SignPrivateKey, msg []byte) (h *big.Int, s *sm9curve.G1, err error) {
    n := sm9curve.Order
    g := sm9curve.Pair(sm9curve.Gen1, pri.Mpk)

Regen:
    r, err := randFieldElement(rand, n)
    if err != nil {
        return nil, nil, errors.Errorf("gen rand num failed:%s", err)
    }

    w := new(sm9curve.GT).ScalarMult(g, r)
    wBytes := w.Marshal()

    msg = append(msg, wBytes...)
    hashed := hash(msg, n, H2)

    h = new(big.Int).Set(hashed)

    l := new(big.Int).Sub(r, hashed)
    l.Mod(l, n)

    if l.BitLen() == 0 {
        goto Regen
    }

    s = new(sm9curve.G1).ScalarMult(pri.Sk, l)

    return
}

// sm9 verify algorithm(given h',S', message M' and user's id):
// B1:compute g = e(P1,Ppub);
// B2:compute t = g^h';
// B3:compute h1 = H1(id||hid,n);
// B4:compute P = h1·P2+Ppub;
// B5:compute u = e(S',P);
// B6:compute w' = u·t;
// B7:compute h2 = H2(M'||w',n), check if h2 = h'.
func Verify(pub *SignMasterPublicKey, id []byte, hid byte, msg []byte, h *big.Int, s *sm9curve.G1) bool {
    n := sm9curve.Order
    g := sm9curve.Pair(sm9curve.Gen1, pub.Mpk)

    t := new(sm9curve.GT).ScalarMult(g, h)

    id = append(id, hid)
    h1 := hash(id, n, H1)

    P := new(sm9curve.G2).ScalarBaseMult(h1)
    P.Add(P, pub.Mpk)

    u := sm9curve.Pair(s, P)
    w := new(sm9curve.GT).Add(u, t)

    wBytes := w.Marshal()
    msg = append(msg, wBytes...)

    h2 := hash(msg, n, H2)
    if h2.Cmp(h) != 0 {
        return false
    }

    return true
}

type sigData struct {
    H []byte
    S asn1.BitString
}

func SignASN1(rand io.Reader, priv *SignPrivateKey, hash []byte) ([]byte, error) {
    h, s, err := Sign(rand, priv, hash)
    if err != nil {
        return nil, err
    }

    r := sigData{
        H: h.Bytes(),
        S: asn1.BitString{
            Bytes: s.Marshal(),
        },
    }

    return asn1.Marshal(r)
}

func VerifyASN1(pub *SignMasterPublicKey, uid []byte, hid byte, hash, sig []byte) bool {
    var data sigData
    if _, err := asn1.Unmarshal(sig, &data); err != nil {
        return false
    }

    s := new(sm9curve.G1)
    _, err := s.Unmarshal(data.S.Bytes)
    if err != nil {
        return false
    }

    h := new(big.Int).SetBytes(data.H)

    return Verify(pub, uid, hid, hash, h, s)
}
