package sm9

import (
    "io"
    "errors"
    "math/big"
    "crypto"
    "crypto/subtle"
    "encoding/asn1"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/kdf/smkdf"
    "github.com/deatil/go-cryptobin/tool/alias"
    "github.com/deatil/go-cryptobin/gm/sm9/sm9curve"
)

// 默认 HID
const DefaultEncryptHid byte = 0x03

var (
    ErrDecryption = errors.New("sm9: decryption error")

    ErrEmptyPlaintext = errors.New("sm9: empty plaintext")
)

// IEncrypt
type IEncrypt interface {
    // Type
    Type() int

    // KeySize
    KeySize() int

    // Encrypt
    Encrypt(rand io.Reader, key, plaintext []byte) ([]byte, error)

    // Decrypt
    Decrypt(key, ciphertext []byte) ([]byte, error)
}

// IHash
type IHash interface {
    // Size
    Size() int

    // Mac
    Mac(k, c []byte) []byte
}

type EncryptMasterPublicKey struct {
    Mpk *sm9curve.G1
}

// Equal reports whether pub and x have the same value.
func (pub *EncryptMasterPublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*EncryptMasterPublicKey)
    if !ok {
        return false
    }

    return pub.Mpk.Equal(xx.Mpk)
}

func (pub *EncryptMasterPublicKey) Encrypt(rand io.Reader, uid []byte, hid byte, plaintext []byte, enc IEncrypt) ([]byte, error) {
    if enc == nil {
        enc = DefaultEncrypt
    }

    opts := &Opts{
        Encrypt: enc,
        Hash:    DefaultHash,
    }

    return EncryptASN1(rand, pub, uid, hid, plaintext, opts)
}

func (pub *EncryptMasterPublicKey) GenerateUserPublicKey(uid []byte, hid byte) (*sm9curve.G1, error) {
    n := sm9curve.Order

    uidh := append(uid, hid)
    h := hash(uidh, n, H1)

    qb, err := new(sm9curve.G1).ScalarBaseMult(sm9curve.NormalizeScalar(h.Bytes()))
    if err != nil {
        return nil, err
    }

    qb.Add(qb, pub.Mpk)

    return qb, nil
}

func (pub *EncryptMasterPublicKey) Marshal() []byte {
    return pub.Mpk.MarshalUncompressed()
}

func (pub *EncryptMasterPublicKey) Unmarshal(bytes []byte) (err error) {
    g := new(sm9curve.G1)
    _, err = g.UnmarshalUncompressed(bytes)
    if err != nil {
        return err
    }

    pub.Mpk = g

    return
}

func (pub *EncryptMasterPublicKey) MarshalCompress() []byte {
    return pub.Mpk.MarshalCompressed()
}

func (pub *EncryptMasterPublicKey) UnmarshalCompress(bytes []byte) (err error) {
    g := new(sm9curve.G1)
    _, err = g.UnmarshalCompressed(bytes)
    if err != nil {
        return err
    }

    pub.Mpk = g

    return
}

type EncryptMasterPrivateKey struct {
    EncryptMasterPublicKey
    D *big.Int
}

// Equal reports whether priv and x have the same value.
func (priv *EncryptMasterPrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*EncryptMasterPrivateKey)
    if !ok {
        return false
    }

    return priv.EncryptMasterPublicKey.Equal(&xx.EncryptMasterPublicKey) &&
        bigIntEqual(priv.D, xx.D)
}

func (priv *EncryptMasterPrivateKey) PublicKey() *EncryptMasterPublicKey {
    return &priv.EncryptMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (priv *EncryptMasterPrivateKey) Public() crypto.PublicKey {
    return priv.PublicKey()
}

// generate user's secret key.
func (priv *EncryptMasterPrivateKey) GenerateUserKey(id []byte, hid byte) (uk *EncryptPrivateKey, err error) {
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

    uk = new(EncryptPrivateKey)

    uk.Sk, err = new(sm9curve.G2).ScalarBaseMult(sm9curve.NormalizeScalar(t2.Bytes()))
    uk.Mpk = priv.Mpk

    return uk, nil
}

func (priv *EncryptMasterPrivateKey) Marshal() []byte {
    return priv.D.Bytes()
}

func (priv *EncryptMasterPrivateKey) Unmarshal(bytes []byte) (err error) {
    priv.D = new(big.Int).SetBytes(bytes)

    d := new(big.Int).SetBytes(sm9curve.NormalizeScalar(bytes))
    priv.Mpk, err = new(sm9curve.G1).ScalarBaseMult(sm9curve.NormalizeScalar(d.Bytes()))

    return
}

type EncryptPrivateKey struct {
    Sk *sm9curve.G2
    EncryptMasterPublicKey
}

// Equal reports whether priv and x have the same value.
func (priv *EncryptPrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*EncryptPrivateKey)
    if !ok {
        return false
    }

    return priv.Sk.Equal(xx.Sk)
}

func (priv *EncryptPrivateKey) PublicKey() *EncryptMasterPublicKey {
    return &priv.EncryptMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (priv *EncryptPrivateKey) Public() crypto.PublicKey {
    return priv.PublicKey()
}

func (priv *EncryptPrivateKey) Decrypt(uid, msg []byte) (plaintext []byte, err error) {
    return DecryptASN1(priv, uid, msg, nil)
}

func (priv *EncryptPrivateKey) Marshal() []byte {
    var pub []byte

    if priv.Mpk != nil {
        pub = priv.Mpk.MarshalUncompressed()
    }

    return append(priv.Sk.MarshalUncompressed(), pub...)
}

func (priv *EncryptPrivateKey) Unmarshal(bytes []byte) (err error) {
    var pub []byte

    g2 := new(sm9curve.G2)
    pub, err = g2.UnmarshalUncompressed(bytes)
    if err != nil {
        return err
    }

    priv.Sk = g2

    if len(pub) > 0 {
        g1 := new(sm9curve.G1)
        _, err = g1.UnmarshalUncompressed(pub)
        if err != nil {
            return err
        }

        priv.Mpk = g1
    }

    return
}

// generate matser's secret encrypt key.
func GenerateEncryptMasterKey(rand io.Reader) (mk *EncryptMasterPrivateKey, err error) {
    k, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, errors.New("gen rand num err:" + err.Error())
    }

    mk = new(EncryptMasterPrivateKey)
    mk.D = new(big.Int).Set(k)
    mk.Mpk, err = new(sm9curve.G1).ScalarBaseMult(sm9curve.NormalizeScalar(k.Bytes()))
    if err != nil {
        return nil, err
    }

    return
}

// generate user's secret encrypt key.
func GenerateEncryptUserKey(priv *EncryptMasterPrivateKey, id []byte, hid byte) (*EncryptPrivateKey, error) {
    return priv.GenerateUserKey(id, hid)
}

// 解析加密主公钥明文
func NewEncryptMasterPublicKey(bytes []byte) (pub *EncryptMasterPublicKey, err error) {
    pub = new(EncryptMasterPublicKey)

    err = pub.Unmarshal(bytes)

    return
}

// 输出加密主公钥明文
func EncryptMasterPublicKeyTo(pub *EncryptMasterPublicKey) []byte {
    return pub.Marshal()
}

// 解析加密主私钥明文
func NewEncryptMasterPrivateKey(bytes []byte) (priv *EncryptMasterPrivateKey, err error) {
    priv = new(EncryptMasterPrivateKey)

    err = priv.Unmarshal(bytes)

    return
}

// 输出加密私钥明文
func EncryptMasterPrivateKeyTo(priv *EncryptMasterPrivateKey) []byte {
    return priv.Marshal()
}

// 解析加密私钥明文
func NewEncryptPrivateKey(bytes []byte) (priv *EncryptPrivateKey, err error) {
    priv = new(EncryptPrivateKey)

    err = priv.Unmarshal(bytes)

    return
}

// 输出明文
func EncryptPrivateKeyTo(priv *EncryptPrivateKey) []byte {
    return priv.Marshal()
}

func WrapKey(random io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, kLen int) (key []byte, C1 *sm9curve.G1, err error) {
    // step 1:qb = [H1(IDb || hid, n)]P1 + mpk
    n := sm9curve.Order

    uid2h := append(uid, hid)

    h := hash(uid2h, n, H1)

    qb, err := new(sm9curve.G1).ScalarMult(sm9curve.Gen1, h.Bytes())
    if err != nil {
        return
    }

    qb.Add(qb, pub.Mpk)

    var r *big.Int

    for {
        r, err = randFieldElement(random, n)
        if err != nil {
            return
        }

        // step 3: c1 = [r]qb
        C1, err = new(sm9curve.G1).ScalarMult(qb, r.Bytes())
        if err != nil {
            return
        }

        // step 4: g = e(mpk, P2)
        g := sm9curve.Pair(pub.Mpk, sm9curve.Gen2)

        // step 5: w = g^r
        w := new(sm9curve.GT).ScalarMult(g, r)

        var buffer []byte
        buffer = append(buffer, C1.Marshal()...)
        buffer = append(buffer, w.Marshal()...)
        buffer = append(buffer, uid...)

        key = smkdf.Key(sm3.New, buffer, kLen)
        if !alias.ConstantTimeAllZero(key) {
            break
        }
    }

    return
}

// UnwrapKey unwraps key from cipher, user id and aligned key length
func UnwrapKey(priv *EncryptPrivateKey, uid []byte, cipher *sm9curve.G1, kLen int) ([]byte, error) {
    w := sm9curve.Pair(cipher, priv.Sk)

    var buffer []byte
    buffer = append(buffer, cipher.Marshal()...)
    buffer = append(buffer, w.Marshal()...)
    buffer = append(buffer, uid...)

    key := smkdf.Key(sm3.New, buffer, kLen)
    if alias.ConstantTimeAllZero(key) {
        return nil, errors.New("sm9: decryption error")
    }

    return key, nil
}

type Opts struct {
    Encrypt IEncrypt
    Hash    IHash
}

var DefaultOpts = &Opts{
    Encrypt: DefaultEncrypt,
    Hash:    DefaultHash,
}

// Encrypt
func Encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts *Opts) ([]byte, error) {
    c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
    if err != nil {
        return nil, err
    }

    ciphertext := append(c1.MarshalUncompressed(), c3...)
    ciphertext = append(ciphertext, c2...)

    return ciphertext, nil
}

// encrypt
func encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts *Opts) (c1 *sm9curve.G1, c2, c3 []byte, err error) {
    if opts == nil {
        opts = DefaultOpts
    }

    enc := opts.Encrypt
    hash := opts.Hash

    if len(plaintext) == 0 {
        return nil, nil, nil, ErrEmptyPlaintext
    }

    key1Len := enc.KeySize()
    if key1Len == 0 {
        key1Len = len(plaintext)
    }

    key, c1, err := WrapKey(rand, pub, uid, hid, key1Len + hash.Size())
    if err != nil {
        return nil, nil, nil, err
    }

    c2, err = enc.Encrypt(rand, key[:key1Len], plaintext)
    if err != nil {
        return nil, nil, nil, err
    }

    c3 = hash.Mac(key[key1Len:], c2)

    return
}

// Decrypt
func Decrypt(priv *EncryptPrivateKey, uid, ciphertext []byte, opts *Opts) ([]byte, error) {
    if opts == nil {
        opts = DefaultOpts
    }

    enc := opts.Encrypt
    hash := opts.Hash

    c := &sm9curve.G1{}
    c3c2, err := c.UnmarshalUncompressed(ciphertext)
    if err != nil {
        return nil, ErrDecryption
    }

    size := hash.Size()

    c3 := c3c2[:size]
    c2 := c3c2[size:]

    key1Len := enc.KeySize()
    if key1Len == 0 {
        key1Len = len(c2)
    }

    key, err := UnwrapKey(priv, uid, c, key1Len + size)
    if err != nil {
        return nil, err
    }

    key1 := key[:key1Len]
    key2 := key[key1Len:]

    mac := hash.Mac(key2, c2)

    if subtle.ConstantTimeCompare(c3, mac) != 1 {
        return nil, ErrDecryption
    }

    return enc.Decrypt(key1, c2)
}

type encryptData struct {
    EncType int
    C1 asn1.BitString
    C3 []byte
    C2 []byte
}

func EncryptASN1(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts *Opts) ([]byte, error) {
    if opts == nil {
        opts = DefaultOpts
    }

    enc := opts.Encrypt

    c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
    if err != nil {
        return nil, err
    }

    r := encryptData{
        EncType: enc.Type(),
        C1: asn1.BitString{
            Bytes: c1.MarshalUncompressed(),
        },
        C3: c3,
        C2: c2,
    }

    return asn1.Marshal(r)
}

func DecryptASN1(priv *EncryptPrivateKey, uid, ciphertext []byte, opts *Opts) ([]byte, error) {
    var data encryptData
    if _, err := asn1.Unmarshal(ciphertext, &data); err != nil {
        return nil, err
    }

    if opts == nil {
        opts = DefaultOpts
    }

    opts.Encrypt = GetEncryptType(data.EncType)
    if opts.Encrypt == nil {
        return nil, errors.New("sm9: not support enc type")
    }

    ct := append(data.C1.Bytes, data.C3...)
    ct = append(ct, data.C2...)

    return Decrypt(priv, uid, ct, opts)
}
