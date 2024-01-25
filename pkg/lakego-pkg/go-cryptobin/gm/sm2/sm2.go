package sm2

import (
    "io"
    "bytes"
    "errors"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
    "crypto/elliptic"
    "encoding/asn1"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/gm/sm2/curve"
)

// sm2 p256
var P256 = curve.P256

var defaultUid = []byte{
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
}

var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

var errZeroParam = errors.New("zero parameter")

// 模式
type Mode uint

const (
    C1C3C2 Mode = 0 + iota
    C1C2C3
)

type EncrypterOpts struct {
    Mode Mode
}

type SignerOpts struct {
    Uid []byte
}

func (opt SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

type sm2Signature struct {
    R, S *big.Int
}

func SignDigitToData(r, s *big.Int) ([]byte, error) {
    return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToDigit(sign []byte) (*big.Int, *big.Int, error) {
    var sm2Sign sm2Signature

    _, err := asn1.Unmarshal(sign, &sm2Sign)
    if err != nil {
        return nil, nil, err
    }

    return sm2Sign.R, sm2Sign.S, nil
}

type PublicKey struct {
    elliptic.Curve
    X, Y *big.Int
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.Curve == xx.Curve &&
        bigIntEqual(pub.X, xx.X) &&
        bigIntEqual(pub.Y, xx.Y)
}

func (pub *PublicKey) Verify(msg []byte, sign []byte, opts crypto.SignerOpts) bool {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    r, s, err := SignDataToDigit(sign)
    if err != nil {
        return false
    }

    return VerifyWithSM2(pub, msg, uid, r, s)
}

func (pub *PublicKey) VerifyBytes(msg []byte, sign []byte, opts crypto.SignerOpts) bool {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    r := new(big.Int).SetBytes(sign[:32])
    s := new(big.Int).SetBytes(sign[32:])

    return VerifyWithSM2(pub, msg, uid, r, s)
}

func (pub *PublicKey) Encrypt(random io.Reader, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return Encrypt(random, pub, data, mode)
}

func (pub *PublicKey) EncryptASN1(random io.Reader, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return EncryptASN1(random, pub, data, mode)
}

type PrivateKey struct {
    PublicKey
    D *big.Int
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(&xx.PublicKey) &&
        bigIntEqual(priv.D, xx.D)
}

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s
func (priv *PrivateKey) Sign(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    r, s, err := SignWithSM2(random, priv, msg, uid)
    if err != nil {
        return nil, err
    }

    return SignDigitToData(r, s)
}

func (priv *PrivateKey) SignBytes(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    uid := defaultUid
    if opt, ok := opts.(SignerOpts); ok {
        uid = opt.Uid
    }

    r, s, err := SignWithSM2(random, priv, msg, uid)
    if err != nil {
        return nil, err
    }

    sign := make([]byte, 64)

    copy(sign[:32], zeroPadding(r.Bytes(), 32))
    copy(sign[32:], zeroPadding(s.Bytes(), 32))

    return sign, nil
}

// crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return Decrypt(priv, msg, mode)
}

func (priv *PrivateKey) DecryptASN1(data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    mode := C1C3C2
    if opt, ok := opts.(EncrypterOpts); ok {
        mode = opt.Mode
    }

    return DecryptASN1(priv, data, mode)
}

func GenerateKey(random io.Reader) (*PrivateKey, error) {
    c := P256()

    if random == nil {
        random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
    }

    params := c.Params()

    b := make([]byte, params.BitSize/8+8)

    _, err := io.ReadFull(random, b)
    if err != nil {
        return nil, err
    }

    k := new(big.Int).SetBytes(b)
    n := new(big.Int).Sub(params.N, two)

    k.Mod(k, n)
    k.Add(k, one)

    priv := new(PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

    return priv, nil
}

// 根据私钥明文初始化私钥
func NewPrivateKey(d []byte) (*PrivateKey, error) {
    k := new(big.Int).SetBytes(d)

    c := P256()
    params := c.Params()

    n := new(big.Int).Sub(params.N, one)
    if k.Cmp(n) >= 0 {
        return nil, errors.New("sm2: privateKey's D is overflow.")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = c
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(d)

    return priv, nil
}

// 输出私钥明文
func ToPrivateKey(key *PrivateKey) []byte {
    return key.D.Bytes()
}

// 根据公钥明文初始化公钥
func NewPublicKey(data []byte) (*PublicKey, error) {
    c := P256()

    x, y := curve.Unmarshal(c, data)
    if x == nil || y == nil {
        return nil, errors.New("sm2: publicKey is incorrect.")
    }

    pub := &PublicKey{
        Curve: c,
        X: x,
        Y: y,
    }

    return pub, nil
}

// 输出公钥明文
func ToPublicKey(key *PublicKey) []byte {
    return curve.Marshal(key.Curve, key.X, key.Y)
}

// sm2 密文结构: x + y + hash + CipherText
func Encrypt(random io.Reader, pub *PublicKey, data []byte, mode Mode) ([]byte, error) {
    ct, err := encrypt(random, pub, data)
    if err != nil {
        return nil, err
    }

    // 编码数据 / Marshal Data
    ct = marshalBytes(ct, mode)

    return ct, nil
}

func Decrypt(priv *PrivateKey, data []byte, mode Mode) ([]byte, error) {
    // 解析数据 / Unmarshal Data
    res, err := unmarshalBytes(data, mode)
    if err != nil {
        return nil, err
    }

    return decrypt(priv, res)
}

// sm2 加密，返回 asn.1 编码格式的密文内容
func EncryptASN1(rand io.Reader, pub *PublicKey, data []byte, mode Mode) ([]byte, error) {
    ct, err := encrypt(rand, pub, data)
    if err != nil {
        return nil, err
    }

    return marshalASN1(ct, mode)
}

// sm2解密，解析 asn.1 编码格式的密文内容
func DecryptASN1(pub *PrivateKey, data []byte, mode Mode) ([]byte, error) {
    res, err := unmarshalASN1(data, mode)
    if err != nil {
        return nil, err
    }

    return decrypt(pub, res)
}

func encrypt(random io.Reader, pub *PublicKey, data []byte) ([]byte, error) {
    length := len(data)

    for {
        c := []byte{}

        curve := pub.Curve

        k, err := randFieldElement(curve, random)
        if err != nil {
            return nil, err
        }

        x1, y1 := curve.ScalarBaseMult(k.Bytes())
        x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

        x1Buf := zeroPadding(x1.Bytes(), 32)
        y1Buf := zeroPadding(y1.Bytes(), 32)
        x2Buf := zeroPadding(x2.Bytes(), 32)
        y2Buf := zeroPadding(y2.Bytes(), 32)

        c = append(c, x1Buf...) // x分量
        c = append(c, y1Buf...) // y分量

        tm := []byte{}
        tm = append(tm, x2Buf...)
        tm = append(tm, data...)
        tm = append(tm, y2Buf...)

        h := sm3.Sum(tm)
        c = append(c, h[:]...)

        ct, ok := kdf(length, x2Buf, y2Buf) // 密文
        if !ok {
            continue
        }

        c = append(c, ct...)

        for i := 0; i < length; i++ {
            c[96+i] ^= data[i]
        }

        return c, nil
    }
}

func decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
    length := len(data) - 96

    curve := priv.Curve

    x := new(big.Int).SetBytes(data[ 0:32])
    y := new(big.Int).SetBytes(data[32:64])

    x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())

    x2Buf := zeroPadding(x2.Bytes(), 32)
    y2Buf := zeroPadding(y2.Bytes(), 32)

    c, ok := kdf(length, x2Buf, y2Buf)
    if !ok {
        return nil, errors.New("sm2: failed to decrypt")
    }

    for i := 0; i < length; i++ {
        c[i] ^= data[i+96]
    }

    tm := []byte{}
    tm = append(tm, x2Buf...)
    tm = append(tm, c...)
    tm = append(tm, y2Buf...)

    h := sm3.Sum(tm)

    if bytes.Compare(h[:], data[64:96]) != 0 {
        return c, errors.New("sm2: failed to decrypt")
    }

    return c, nil
}

func Sign(random io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
    e := new(big.Int).SetBytes(hash)
    c := priv.PublicKey.Curve

    N := c.Params().N
    if N.Sign() == 0 {
        return nil, nil, errZeroParam
    }

    var k *big.Int

    for {
        for {
            k, err = randFieldElement(c, random)
            if err != nil {
                r = nil
                return
            }

            r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
            r.Add(r, e)
            r.Mod(r, N)

            if r.Sign() != 0 {
                if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
                    break
                }
            }

        }

        rD := new(big.Int).Mul(priv.D, r)
        s = new(big.Int).Sub(k, rD)

        d1 := new(big.Int).Add(priv.D, one)
        d1Inv := new(big.Int).ModInverse(d1, N)

        s.Mul(s, d1Inv)
        s.Mod(s, N)

        if s.Sign() != 0 {
            break
        }
    }

    return
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
    c := pub.Curve
    N := c.Params().N

    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false
    }

    if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
        return false
    }

    t := new(big.Int).Add(r, s)
    t.Mod(t, N)
    if t.Sign() == 0 {
        return false
    }

    var x *big.Int

    x1, y1 := c.ScalarBaseMult(s.Bytes())
    x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
    x, _ = c.Add(x1, y1, x2, y2)

    e := new(big.Int).SetBytes(hash)
    x.Add(x, e)
    x.Mod(x, N)

    return x.Cmp(r) == 0
}

func SignWithSM2(random io.Reader, priv *PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
    hash, err := CalculateSM2Hash(&priv.PublicKey, msg, uid)
    if err != nil {
        return nil, nil, err
    }

    return Sign(random, priv, hash)
}

func VerifyWithSM2(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
    hash, err := CalculateSM2Hash(pub, msg, uid)
    if err != nil {
        return false
    }

    return Verify(pub, hash, r, s)
}

func CalculateSM2Hash(pub *PublicKey, msg, uid []byte) ([]byte, error) {
    if len(uid) == 0 {
        uid = defaultUid
    }

    za, err := CalculateZA(pub, uid)
    if err != nil {
        return nil, err
    }

    md := sm3.New()
    md.Write(za)
    md.Write(msg)

    return md.Sum(nil), nil
}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func CalculateZA(pub *PublicKey, uid []byte) ([]byte, error) {
    uidLen := len(uid)
    if uidLen >= 8192 {
        return []byte{}, errors.New("sm2: uid too large")
    }

    entla := uint16(8 * uidLen)

    md := sm3.New()
    md.Write([]byte{byte((entla >> 8) & 0xFF)})
    md.Write([]byte{byte(entla & 0xFF)})

    if uidLen > 0 {
        md.Write(uid)
    }

    params := pub.Curve.Params()

    a := new(big.Int).Sub(params.P, big.NewInt(3))

    md.Write(a.Bytes())
    md.Write(params.B.Bytes())
    md.Write(params.Gx.Bytes())
    md.Write(params.Gy.Bytes())
    md.Write(bigIntToBytes(pub.Curve, pub.X))
    md.Write(bigIntToBytes(pub.Curve, pub.Y))

    return md.Sum(nil), nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
    if random == nil {
        // If there is no external trusted random source,
        // please use rand.Reader to instead of it.
        random = rand.Reader
    }

    params := c.Params()

    b := make([]byte, params.BitSize/8+8)

    _, err = io.ReadFull(random, b)
    if err != nil {
        return
    }

    k = new(big.Int).SetBytes(b)
    n := new(big.Int).Sub(params.N, one)

    k.Mod(k, n)
    k.Add(k, one)

    return
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
    var c []byte

    ct := 1
    h := sm3.New()

    for i, j := 0, (length+31)/32; i < j; i++ {
        h.Reset()
        for _, xx := range x {
            h.Write(xx)
        }

        h.Write(intToBytes(ct))

        hash := h.Sum(nil)
        if i+1 == j && length%32 != 0 {
            c = append(c, hash[:length%32]...)
        } else {
            c = append(c, hash...)
        }

        ct++
    }

    for i := 0; i < length; i++ {
        if c[i] != 0 {
            return c, true
        }
    }

    return c, false
}

func intToBytes(x int) []byte {
    var buf = make([]byte, 4)
    binary.BigEndian.PutUint32(buf, uint32(x))

    return buf
}

func bigIntToBytes(c elliptic.Curve, value *big.Int) []byte {
    byteLen := (c.Params().BitSize + 7) / 8

    buf := make([]byte, byteLen)
    value.FillBytes(buf)

    return buf
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// zero padding
func zeroPadding(text []byte, size int) []byte {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        r := bytes.Repeat([]byte("0"), size - n)
        return append(r, text...)
    }

    return text[n-size:]
}
