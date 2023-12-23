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
    "github.com/deatil/go-cryptobin/gm/sm9/sm9curve"
    cryptobin_subtle "github.com/deatil/go-cryptobin/tool/subtle"
)

// 默认 HID
const DefaultEncryptHid byte = 0x01

var ErrDecryption = errors.New("sm9: decryption error")

var ErrEmptyPlaintext = errors.New("sm9: empty plaintext")

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

    // Hash
    Hash(c, k []byte) []byte
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

func (this *EncryptMasterPrivateKey) PublicKey() *EncryptMasterPublicKey {
    return &this.EncryptMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (this *EncryptMasterPrivateKey) Public() crypto.PublicKey {
    return this.PublicKey()
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

func (this *EncryptPrivateKey) PublicKey() *EncryptMasterPublicKey {
    return &this.EncryptMasterPublicKey
}

// Public returns the public key corresponding to priv.
func (this *EncryptPrivateKey) Public() crypto.PublicKey {
    return this.PublicKey()
}

// generate matser's secret encrypt key.
func GenerateEncryptMasterPrivateKey(rand io.Reader) (mk *EncryptMasterPrivateKey, err error) {
    k, err := randFieldElement(rand, sm9curve.Order)
    if err != nil {
        return nil, errors.New("gen rand num err:" + err.Error())
    }

    mk = new(EncryptMasterPrivateKey)
    mk.D = new(big.Int).Set(k)
    mk.Mpk = new(sm9curve.G1).ScalarBaseMult(k)

    return
}

// generate user's secret encrypt key.
func GenerateEncryptPrivateKey(mk *EncryptMasterPrivateKey, id []byte, hid byte) (uk *EncryptPrivateKey, err error) {
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

    uk = new(EncryptPrivateKey)
    uk.Sk = new(sm9curve.G2).ScalarBaseMult(t2)
    uk.Mpk = mk.Mpk

    return
}

func NewEncryptMasterPrivateKey(bytes []byte) (mke *EncryptMasterPrivateKey, err error) {
    mke = new(EncryptMasterPrivateKey)

    mke.D = new(big.Int).SetBytes(bytes)

    d := new(big.Int).SetBytes(sm9curve.NormalizeScalar(bytes))
    mke.Mpk = new(sm9curve.G1).ScalarBaseMult(d)

    return
}

// 输出明文
func ToEncryptMasterPrivateKey(mke *EncryptMasterPrivateKey) []byte {
    return mke.D.Bytes()
}

func NewEncryptMasterPublicKey(bytes []byte) (mbk *EncryptMasterPublicKey, err error) {
    g := new(sm9curve.G1)
    _, err = g.Unmarshal(bytes)
    if err != nil {
        return nil, err
    }

    mbk = new(EncryptMasterPublicKey)
    mbk.Mpk = g

    return
}

// 输出明文
func ToEncryptMasterPublicKey(pub *EncryptMasterPublicKey) []byte {
    return pub.Mpk.Marshal()
}

func NewEncryptPrivateKey(bytes []byte) (uke *EncryptPrivateKey, err error) {
    var pub []byte

    g2 := new(sm9curve.G2)
    pub, err = g2.Unmarshal(bytes)
    if err != nil {
        return nil, err
    }

    uke = new(EncryptPrivateKey)
    uke.Sk = g2

    if len(pub) > 0 {
        g1 := new(sm9curve.G1)
        _, err = g1.Unmarshal(pub)
        if err != nil {
            return nil, err
        }

        uke.Mpk = g1
    }

    return
}

// 输出明文
func ToEncryptPrivateKey(pri *EncryptPrivateKey) []byte {
    var pub []byte

    if pri.Mpk != nil {
        pub = pri.Mpk.Marshal()
    }

    return append(pri.Sk.Marshal(), pub...)
}

func WrapKey(random io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, kLen int) (key []byte, C1 *sm9curve.G1, err error) {
    // step 1:qb = [H1(IDb || hid, n)]P1 + mpk
    n := sm9curve.Order

    uid2h := append(uid, hid)

    h := hash(uid2h, n, H1)

    qb := new(sm9curve.G1).ScalarMult(sm9curve.Gen1, h)
    qb.Add(qb, pub.Mpk)

    var r *big.Int

    for {
        r, err = randFieldElement(random, n)
        if err != nil {
            return
        }

        // step 3: c1 = [r]qb
        C1 = new(sm9curve.G1).ScalarMult(qb, r)

        // step 4: g = e(mpk, P2)
        g := sm9curve.Pair(pub.Mpk, sm9curve.Gen2)

        // step 5: w = g^r
        w := new(sm9curve.GT).ScalarMult(g, r)

        var buffer []byte
        buffer = append(buffer, C1.Marshal()...)
        buffer = append(buffer, w.Marshal()...)
        buffer = append(buffer, uid...)

        key = smkdf.Key(sm3.New, buffer, kLen)
        if !cryptobin_subtle.ConstantTimeAllZero(key) {
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
    if cryptobin_subtle.ConstantTimeAllZero(key) {
        return nil, errors.New("sm9: decryption error")
    }

    return key, nil
}

type Opts struct {
    Encrypt IEncrypt
    Hash    IHash
}

var DefaultOpts = &Opts{
    Encrypt: SM4CBCEncrypt,
    Hash:    HmacSM3Hash,
}

func Encrypt(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, opts *Opts) ([]byte, error) {
    c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
    if err != nil {
        return nil, err
    }

    ciphertext := append(c1.Marshal(), c3...)
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

    c3 = hash.Hash(c2, key[key1Len:])

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
    c3c2, err := c.Unmarshal(ciphertext)
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

    c32 := hash.Hash(c2, key2)

    if subtle.ConstantTimeCompare(c3, c32) != 1 {
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

func EncryptASN1(rand io.Reader, pub *EncryptMasterPublicKey, uid []byte, hid byte, plaintext []byte, enc IEncrypt) ([]byte, error) {
    if enc == nil {
        enc = DefaultEncrypt
    }

    opts := &Opts{
        Encrypt: enc,
        Hash:    HmacSM3Hash,
    }

    c1, c2, c3, err := encrypt(rand, pub, uid, hid, plaintext, opts)
    if err != nil {
        return nil, err
    }

    r := encryptData{
        EncType: enc.Type(),
        C1: asn1.BitString{
            Bytes: c1.Marshal(),
        },
        C3: c3,
        C2: c2,
    }

    return asn1.Marshal(r)
}

func DecryptASN1(priv *EncryptPrivateKey, uid, ciphertext []byte) ([]byte, error) {
    var data encryptData
    if _, err := asn1.Unmarshal(ciphertext, &data); err != nil {
        return nil, err
    }

    encType := GetEncryptType(data.EncType)

    opts := &Opts{
        Encrypt: encType,
        Hash:    HmacSM3Hash,
    }

    ct := append(data.C1.Bytes, data.C3...)
    ct = append(ct, data.C2...)

    return Decrypt(priv, uid, ct, opts)
}
