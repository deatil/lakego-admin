package sm9

import (
    "io"
    "fmt"
    "errors"
    "crypto"
    "math/big"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/gm/sm9/sm9curve"
)

// 默认 HID
const DefaultSignHid byte = 0x01

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

func (pub *SignMasterPublicKey) Verify(uid []byte, hid byte, hash, sig []byte) bool {
    return VerifyASN1(pub, uid, hid, hash, sig)
}

func (pub *SignMasterPublicKey) GenerateUserPublicKey(uid []byte, hid byte) (*sm9curve.G2, error) {
    n := sm9curve.Order

    uidh := append(uid, hid)
    h := hash(uidh, n, H1)

    qb, err := new(sm9curve.G2).ScalarBaseMult(sm9curve.NormalizeScalar(h.Bytes()))
    if err != nil {
        return nil, err
    }

    qb.Add(qb, pub.Mpk)

    return qb, nil
}

func (pub *SignMasterPublicKey) Marshal() []byte {
    return pub.Mpk.MarshalUncompressed()
}

func (pub *SignMasterPublicKey) Unmarshal(bytes []byte) (err error) {
    g := new(sm9curve.G2)
    _, err = g.UnmarshalUncompressed(bytes)
    if err != nil {
        return err
    }

    pub.Mpk = g

    return
}

// 压缩明文
func (pub *SignMasterPublicKey) MarshalCompress() []byte {
    return pub.Mpk.MarshalCompressed()
}

// 解压缩明文
func (pub *SignMasterPublicKey) UnmarshalCompress(bytes []byte) (err error) {
    g := new(sm9curve.G2)
    _, err = g.UnmarshalCompressed(bytes)
    if err != nil {
        return err
    }

    pub.Mpk = g

    return
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

func (priv *SignMasterPrivateKey) PublicKey() *SignMasterPublicKey {
    return &priv.SignMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (priv *SignMasterPrivateKey) Public() crypto.PublicKey {
    return priv.PublicKey()
}

// generate user's secret key.
func (priv *SignMasterPrivateKey) GenerateUserKey(id []byte, hid byte) (uk *SignPrivateKey, err error) {
    id = append(id, hid)
    n := sm9curve.Order

    t1 := hash(id, n, H1)
    t1.Add(t1, priv.D)

    // if t1 = 0, we need to regenerate the master key.
    if t1.BitLen() == 0 || t1.Cmp(n) == 0 {
        return nil, errors.New("need to regen MasterPrivateKey!")
    }

    t1.ModInverse(t1, n)

    // t2 = s*t1^-1
    t2 := new(big.Int).Mul(priv.D, t1)

    uk = new(SignPrivateKey)
    uk.Sk, err = new(sm9curve.G1).ScalarBaseMult(sm9curve.NormalizeScalar(t2.Bytes()))
    uk.Mpk = priv.Mpk

    return
}

func (priv *SignMasterPrivateKey) Marshal() []byte {
    return priv.D.Bytes()
}

func (priv *SignMasterPrivateKey) Unmarshal(bytes []byte) (err error) {
    priv.D = new(big.Int).SetBytes(bytes)

    d := new(big.Int).SetBytes(sm9curve.NormalizeScalar(bytes))
    priv.Mpk, err = new(sm9curve.G2).ScalarBaseMult(sm9curve.NormalizeScalar(d.Bytes()))

    return
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

func (priv *SignPrivateKey) PublicKey() *SignMasterPublicKey {
    return &priv.SignMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (priv *SignPrivateKey) Public() crypto.PublicKey {
    return priv.PublicKey()
}

// Sign
func (priv *SignPrivateKey) Sign(rand io.Reader, hash []byte) ([]byte, error) {
    return SignASN1(rand, priv, hash)
}

func (priv *SignPrivateKey) Marshal() []byte {
    if priv.Mpk == nil {
        return nil
    }

    pub := priv.Mpk.MarshalUncompressed()

    return append(priv.Sk.MarshalUncompressed(), pub...)
}

func (priv *SignPrivateKey) Unmarshal(bytes []byte) (err error) {
    var pub []byte

    g1 := new(sm9curve.G1)
    pub, err = g1.UnmarshalUncompressed(bytes)
    if err != nil {
        return err
    }

    if len(pub) == 0 {
        return errors.New("private key need publickey bytes")
    }

    priv.Sk = g1

    g2 := new(sm9curve.G2)
    _, err = g2.UnmarshalUncompressed(pub)
    if err != nil {
        return err
    }

    priv.Mpk = g2

    return
}

// generate master key for KGC(Key Generate Center).
func GenerateSignMasterKey(rand io.Reader) (mk *SignMasterPrivateKey, err error) {
    s, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, errors.New(fmt.Sprintf("gen rand num err: %s", err))
    }

    mk = new(SignMasterPrivateKey)
    mk.D = new(big.Int).Set(s)
    mk.Mpk, err = new(sm9curve.G2).ScalarBaseMult(sm9curve.NormalizeScalar(s.Bytes()))

    return
}

// generate user's secret key.
func GenerateSignUserKey(mk *SignMasterPrivateKey, id []byte, hid byte) (*SignPrivateKey, error) {
    return mk.GenerateUserKey(id, hid)
}

// 解析签名主公钥明文
func NewSignMasterPublicKey(bytes []byte) (pub *SignMasterPublicKey, err error) {
    pub = new(SignMasterPublicKey)

    err = pub.Unmarshal(bytes)

    return
}

// 输出签名主公钥明文
func SignMasterPublicKeyTo(pub *SignMasterPublicKey) []byte {
    return pub.Marshal()
}

// 解析签名主私钥明文
func NewSignMasterPrivateKey(bytes []byte) (priv *SignMasterPrivateKey, err error) {
    priv = new(SignMasterPrivateKey)

    err = priv.Unmarshal(bytes)

    return
}

// 输出签名主私钥明文
func SignMasterPrivateKeyTo(priv *SignMasterPrivateKey) []byte {
    return priv.Marshal()
}

// 解析签名私钥明文
func NewSignPrivateKey(bytes []byte) (priv *SignPrivateKey, err error) {
    priv = new(SignPrivateKey)

    err = priv.Unmarshal(bytes)

    return
}

// 输出签名私钥明文
func SignPrivateKeyTo(priv *SignPrivateKey) []byte {
    return priv.Marshal()
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
        return nil, nil, errors.New(fmt.Sprintf("gen rand num failed: %s", err))
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

    s, err = new(sm9curve.G1).ScalarMult(pri.Sk, l.Bytes())

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

    P, err := new(sm9curve.G2).ScalarBaseMult(sm9curve.NormalizeScalar(h1.Bytes()))
    if err != nil {
        return false
    }

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
            Bytes: s.MarshalUncompressed(),
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
    _, err := s.UnmarshalUncompressed(data.S.Bytes)
    if err != nil {
        return false
    }

    h := new(big.Int).SetBytes(data.H)

    return Verify(pub, uid, hid, hash, h, s)
}
