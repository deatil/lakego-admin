package sm2

import (
    "io"
    "fmt"
    "hash"
    "bytes"
    "errors"
    "math/big"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
    "crypto/elliptic"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/hash/sm3"
    "github.com/deatil/go-cryptobin/kdf/smkdf"
    "github.com/deatil/go-cryptobin/tool/alias"
    "github.com/deatil/go-cryptobin/gm/sm2/sm2curve"
)

var (
    one = new(big.Int).SetInt64(1)
    two = new(big.Int).SetInt64(2)
)

var (
    errZeroParam  = errors.New("cryptobin/sm2: zero parameter")
    errDecryption = errors.New("cryptobin/sm2: failed to decrypt")

    errPrivateKey = errors.New("cryptobin/sm2: incorrect private key")
    errPublicKey  = errors.New("cryptobin/sm2: incorrect public key")

    errSignature  = errors.New("cryptobin/sm2: signature contained zero or negative values")
)

const maxRetryLimit = 100

// the uid will use when not set uid
var defaultUID = []byte{
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
}

// sm2 p256
func P256() elliptic.Curve {
    return sm2curve.P256()
}

type hashFunc = func() hash.Hash

// 加密后数据编码模式
// Encrypted data encoding mode
type Mode uint

const (
    C1C3C2 Mode = 1 + iota
    C1C2C3
)

// 数据编码方式
// marshal data mode
type Encoding uint

const (
    EncodingASN1 Encoding = 1 + iota
    EncodingBytes
)

// 加密设置
// Encrypter Opts
type EncrypterOpts struct {
    Mode     Mode
    Hash     hashFunc
    Encoding Encoding
}

func (this EncrypterOpts) GetMode() Mode {
    switch this.Mode {
        case C1C3C2, C1C2C3:
            return this.Mode
        default:
            return C1C3C2
    }
}

func (this EncrypterOpts) GetHash() hashFunc {
    if this.Hash != nil {
        return this.Hash
    }

    return sm3.New
}

func (this EncrypterOpts) GetEncoding() Encoding {
    switch this.Encoding {
        case EncodingASN1, EncodingBytes:
            return this.Encoding
        default:
            return EncodingBytes
    }
}

// 签名设置
// Signer Opts
type SignerOpts struct {
    Uid      []byte
    Hash     hashFunc
    Encoding Encoding
}

func (this SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

func (this SignerOpts) GetUid() []byte {
    if this.Uid != nil {
        return this.Uid
    }

    return defaultUID
}

func (this SignerOpts) GetHash() hashFunc {
    if this.Hash != nil {
        return this.Hash
    }

    return sm3.New
}

func (this SignerOpts) GetEncoding() Encoding {
    switch this.Encoding {
        case EncodingASN1, EncodingBytes:
            return this.Encoding
        default:
            return EncodingASN1
    }
}

var (
    // default Signer Opts
    DefaultSignerOpts = SignerOpts{
        Uid:  defaultUID,
        Hash: sm3.New,
    }

    // default Encrypter Opts
    DefaultEncrypterOpts = EncrypterOpts{
        Mode: C1C3C2,
        Hash: sm3.New,
    }
)

// SM2 PublicKey
type PublicKey struct {
    elliptic.Curve
    X, Y *big.Int
}

// Size returns the maximum length of the shared key the
// public key can produce.
func (pub *PublicKey) Size() int {
    return (pub.Curve.Params().BitSize + 7) / 8
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.Curve == xx.Curve &&
        bigIntEqual(pub.X, xx.X) &&
        bigIntEqual(pub.Y, xx.Y)
}

// 验证 asn.1 编码的数据 ans1(r, s)
// Verify asn.1 marshal data
func (pub *PublicKey) Verify(msg, sign []byte, opts crypto.SignerOpts) bool {
    opt := DefaultSignerOpts
    if o, ok := opts.(SignerOpts); ok {
        opt = o
    }

    var r, s *big.Int
    var err error

    switch opt.GetEncoding() {
        case EncodingASN1:
            r, s, err = UnmarshalSignatureASN1(sign)
        case EncodingBytes:
            r, s, err = UnmarshalSignatureBytes(pub.Curve, sign)
    }

    if err != nil {
        return false
    }

    err = VerifyWithRS(pub, msg, r, s, opt)
    if err != nil {
        return false
    }

    return true
}

// 验证 asn.1 编码的数据 bytes(r + s)
// Verify Bytes marshal data
func (pub *PublicKey) VerifyBytes(msg, sign []byte, opts crypto.SignerOpts) bool {
    r, s, err := UnmarshalSignatureBytes(pub.Curve, sign)
    if err != nil {
        return false
    }

    err = VerifyWithRS(pub, msg, r, s, opts)
    if err != nil {
        return false
    }

    return true
}

// Encrypt with bytes
func (pub *PublicKey) Encrypt(random io.Reader, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    opt := DefaultEncrypterOpts
    if o, ok := opts.(EncrypterOpts); ok {
        opt = o
    }

    ct, err := encrypt(random, pub, data, opt.GetHash())
    if err != nil {
        return nil, err
    }

    switch opt.GetEncoding() {
        case EncodingASN1:
            res, err := marshalCipherASN1(ct, opt.GetMode())
            if err == nil {
                return res, nil
            }
        case EncodingBytes:
            res := marshalCipherBytes(ct, opt.GetMode())
            return res, nil
    }

    return nil, errors.New("cryptobin/sm2: Encrypt fail")
}

// Encrypt with ASN1
func (pub *PublicKey) EncryptASN1(random io.Reader, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    opt := DefaultEncrypterOpts
    if o, ok := opts.(EncrypterOpts); ok {
        opt = o
    }

    ct, err := encrypt(random, pub, data, opt.GetHash())
    if err != nil {
        return nil, err
    }

    res, err := marshalCipherASN1(ct, opt.GetMode())
    if err == nil {
        return res, nil
    }

    return nil, errors.New("cryptobin/sm2: Encrypt fail")
}

// SM2 PrivateKey
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

// 签名返回 asn.1 编码数据
// sign data and return asn.1 marshal data
func (priv *PrivateKey) Sign(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    opt := DefaultSignerOpts
    if o, ok := opts.(SignerOpts); ok {
        opt = o
    }

    r, s, err := SignToRS(random, priv, msg, opts)
    if err != nil {
        return nil, err
    }

    switch opt.GetEncoding() {
        case EncodingASN1:
            res, err := MarshalSignatureASN1(r, s)
            if err == nil {
                return res, nil
            }
        case EncodingBytes:
            return MarshalSignatureBytes(priv.Curve, r, s)
    }

    return nil, errors.New("cryptobin/sm2: Sign fail")
}

// 签名返回 Bytes 编码数据
// sign data and return Bytes marshal data
func (priv *PrivateKey) SignBytes(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    r, s, err := SignToRS(random, priv, msg, opts)
    if err != nil {
        return nil, err
    }

    return MarshalSignatureBytes(priv.Curve, r, s)
}

// crypto.Decrypter
func (priv *PrivateKey) Decrypt(_ io.Reader, data []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
    opt := DefaultEncrypterOpts
    if o, ok := opts.(EncrypterOpts); ok {
        opt = o
    }

    var res encryptedData

    switch opt.GetEncoding() {
        case EncodingASN1:
            // 解析数据 / Unmarshal Data
            res, err = unmarshalCipherASN1(priv.Curve, data, opt.GetMode())
            if err != nil {
                return nil, err
            }
        case EncodingBytes:
            // 解析数据 / Unmarshal Data
            res, err = unmarshalCipherBytes(priv.Curve, data, opt.GetMode(), opt.GetHash())
            if err != nil {
                return nil, err
            }
    }

    return decrypt(priv, res, opt.GetHash())
}

// Decrypt with ASN1
func (priv *PrivateKey) DecryptASN1(data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    opt := DefaultEncrypterOpts
    if o, ok := opts.(EncrypterOpts); ok {
        opt = o
    }

    // 解析数据 / Unmarshal Data
    res, err := unmarshalCipherASN1(priv.Curve, data, opt.GetMode())
    if err != nil {
        return nil, err
    }

    return decrypt(priv, res, opt.GetHash())
}

// 生成私钥证书
// generate PrivateKey
func GenerateKey(random io.Reader) (*PrivateKey, error) {
    curve := P256()

    k, err := randFieldElement(random, curve)
    if err != nil {
        return nil, err
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())

    return priv, nil
}

// 根据私钥明文初始化私钥
// New a PrivateKey from privatekey data
func NewPrivateKey(d []byte) (*PrivateKey, error) {
    k := new(big.Int).SetBytes(d)

    curve := P256()

    n := new(big.Int).Sub(curve.Params().N, one)
    if k.Cmp(n) >= 0 {
        return nil, errors.New("cryptobin/sm2: privateKey's D is overflow")
    }

    priv := new(PrivateKey)
    priv.PublicKey.Curve = curve
    priv.D = k
    priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d)

    return priv, nil
}

// 输出私钥明文
// output PrivateKey data
func ToPrivateKey(key *PrivateKey) []byte {
    return key.D.Bytes()
}

// 根据公钥明文初始化公钥
// New a PublicKey from publicKey data
func NewPublicKey(data []byte) (*PublicKey, error) {
    curve := P256()

    x, y := sm2curve.Unmarshal(curve, data)
    if x == nil || y == nil {
        return nil, errors.New("cryptobin/sm2: incorrect public key")
    }

    pub := &PublicKey{
        Curve: curve,
        X: x,
        Y: y,
    }

    return pub, nil
}

// 输出公钥明文
// output PublicKey data
func ToPublicKey(key *PublicKey) []byte {
    return sm2curve.Marshal(key.Curve, key.X, key.Y)
}

// sm2 加密，返回字节拼接格式的密文内容
// Encrypted and return bytes data
func Encrypt(random io.Reader, pub *PublicKey, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    if pub == nil {
        return nil, errPublicKey
    }

    return pub.Encrypt(random, data, opts)
}

// sm2 解密，解析字节拼接格式的密文内容
// Decrypt bytes marshal data
func Decrypt(priv *PrivateKey, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    if priv == nil {
        return nil, errPrivateKey
    }

    return priv.Decrypt(nil, data, opts)
}

// sm2 加密，返回 asn.1 编码格式的密文内容
// Encrypted and return asn.1 data
func EncryptASN1(random io.Reader, pub *PublicKey, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    if pub == nil {
        return nil, errPublicKey
    }

    return pub.EncryptASN1(random, data, opts)
}

// sm2 解密，解析 asn.1 编码格式的密文内容
// Decrypt asn.1 marshal data
func DecryptASN1(priv *PrivateKey, data []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    if priv == nil {
        return nil, errPrivateKey
    }

    return priv.DecryptASN1(data, opts)
}

// encrypted Data
type encryptedData struct {
    XCoordinate []byte
    YCoordinate []byte
    Hash        []byte
    CipherText  []byte
}

func encrypt(random io.Reader, pub *PublicKey, data []byte, h hashFunc) (encryptedData, error) {
    length := len(data)

    var retryCount int = 0

    for {
        curve := pub.Curve

        k, err := randFieldElement(random, curve)
        if err != nil {
            return encryptedData{}, err
        }

        x1, y1 := curve.ScalarBaseMult(k.Bytes())
        x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

        x1Buf := bigIntToBytes(pub.Curve, x1)
        y1Buf := bigIntToBytes(pub.Curve, y1)
        x2Buf := bigIntToBytes(pub.Curve, x2)
        y2Buf := bigIntToBytes(pub.Curve, y2)

        md := h()
        md.Write(x2Buf)
        md.Write(data)
        md.Write(y2Buf)

        hashed := md.Sum(nil)

        // 生成密钥 / make key
        ct := smkdf.Key(h, append(x2Buf, y2Buf...), length)

        // 检测生成数据 / check ct data
        if alias.ConstantTimeAllZero(ct) {
            retryCount++
            if retryCount > maxRetryLimit {
                return encryptedData{}, fmt.Errorf("cryptobin/sm2: failed to retry, tried %d times", retryCount)
            }

            continue
        }

        // 生成密文 / make encrypt data
        subtle.XORBytes(ct, ct, data)

        return encryptedData{
            XCoordinate: x1Buf, // x分量
            YCoordinate: y1Buf, // y分量
            Hash:        hashed,
            CipherText:  ct,
        }, nil
    }
}

func decrypt(priv *PrivateKey, data encryptedData, h hashFunc) ([]byte, error) {
    curve := priv.Curve

    x := bytesToBigInt(data.XCoordinate)
    y := bytesToBigInt(data.YCoordinate)

    x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())

    x2Buf := bigIntToBytes(curve, x2)
    y2Buf := bigIntToBytes(curve, y2)

    hash := data.Hash
    cipherText := data.CipherText

    // 生成密钥 / make key
    c := smkdf.Key(h, append(x2Buf, y2Buf...), len(cipherText))

    if alias.ConstantTimeAllZero(c) {
        return nil, errDecryption
    }

    // 解密密文 / decrypt cipherText
    subtle.XORBytes(c, c, cipherText)

    md := h()
    md.Write(x2Buf)
    md.Write(c)
    md.Write(y2Buf)
    hashed := md.Sum(nil)

    if bytes.Compare(hashed, hash) != 0 {
        return nil, errDecryption
    }

    return c, nil
}

// 签名返回 asn.1 编码数据
// sign data and return asn.1 marshal data
func Sign(random io.Reader, priv *PrivateKey, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    if priv == nil {
        return nil, errPrivateKey
    }

    return priv.Sign(random, msg, opts)
}

// 验证 asn.1 编码的数据 ans1(r, s)
// Verify asn.1 marshal data
func Verify(pub *PublicKey, msg, sign []byte, opts crypto.SignerOpts) error {
    if pub == nil {
        return errPublicKey
    }

    ok := pub.Verify(msg, sign, opts)
    if !ok {
        return errors.New("cryptobin/sm2: incorrect signature")
    }

    return nil
}

// 签名返回 Bytes 编码数据
// sign data and return Bytes marshal data
func SignBytes(random io.Reader, priv *PrivateKey, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    if priv == nil {
        return nil, errPrivateKey
    }

    return priv.SignBytes(random, msg, opts)
}

// 验证 asn.1 编码的数据 bytes(r + s)
// Verify Bytes marshal data
func VerifyBytes(pub *PublicKey, msg, sign []byte, opts crypto.SignerOpts) error {
    if pub == nil {
        return errPublicKey
    }

    ok := pub.VerifyBytes(msg, sign, opts)
    if !ok {
        return errors.New("cryptobin/sm2: incorrect signature")
    }

    return nil
}

// sm2 sign with SignerOpts
func SignToRS(random io.Reader, priv *PrivateKey, msg []byte, opts crypto.SignerOpts) (r, s *big.Int, err error) {
    opt := DefaultSignerOpts
    if o, ok := opts.(SignerOpts); ok {
        opt = o
    }

    hashed, err := calculateHash(&priv.PublicKey, opt.GetHash(), msg, opt.GetUid())
    if err != nil {
        return nil, nil, err
    }

    return sign(random, priv, hashed)
}

// sm2 verify with SignerOpts
func VerifyWithRS(pub *PublicKey, msg []byte, r, s *big.Int, opts crypto.SignerOpts) error {
    opt := DefaultSignerOpts
    if o, ok := opts.(SignerOpts); ok {
        opt = o
    }

    hashed, err := calculateHash(pub, opt.GetHash(), msg, opt.GetUid())
    if err != nil {
        return err
    }

    return verify(pub, hashed, r, s)
}

// sm2 sign legacy
func SignLegacy(random io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
    return sign(random, priv, hash)
}

// sm2 verify legacy
func VerifyLegacy(pub *PublicKey, hash []byte, r, s *big.Int) error {
    return verify(pub, hash, r, s)
}

// sm2 sign
func sign(random io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
    e := new(big.Int).SetBytes(hash)
    curve := priv.PublicKey.Curve

    N := curve.Params().N
    if N.Sign() == 0 {
        return nil, nil, errZeroParam
    }

    var k *big.Int

    for {
        for {
            k, err = randFieldElement(random, curve)
            if err != nil {
                r = nil
                return
            }

            r, _ = curve.ScalarBaseMult(k.Bytes())
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

// sm2 verify
func verify(pub *PublicKey, hash []byte, r, s *big.Int) error {
    curve := pub.Curve
    N := curve.Params().N

    if r.Sign() <= 0 || s.Sign() <= 0 {
        return errSignature
    }
    if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
        return errSignature
    }

    t := new(big.Int).Add(r, s)
    t.Mod(t, N)
    if t.Sign() == 0 {
        return errSignature
    }

    var x *big.Int

    x1, y1 := curve.ScalarBaseMult(s.Bytes())
    x2, y2 := curve.ScalarMult(pub.X, pub.Y, t.Bytes())
    x, _ = curve.Add(x1, y1, x2, y2)

    e := new(big.Int).SetBytes(hash)
    x.Add(x, e)
    x.Mod(x, N)

    if x.Cmp(r) != 0 {
        return errors.New("cryptobin/sm2: verification failure")
    }

    return nil
}

func calculateHash(pub *PublicKey, h hashFunc, msg, uid []byte) ([]byte, error) {
    if len(uid) == 0 {
        uid = defaultUID
    }

    za, err := calculateZA(pub, h, uid)
    if err != nil {
        return nil, err
    }

    md := h()
    md.Write(za)
    md.Write(msg)

    return md.Sum(nil), nil
}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func CalculateZA(pub *PublicKey, uid []byte) ([]byte, error) {
    return calculateZA(pub, sm3.New, uid)
}

// CalculateZALegacy ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func CalculateZALegacy(pub *PublicKey, h hashFunc, uid []byte) ([]byte, error) {
    return calculateZA(pub, h, uid)
}

// calculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func calculateZA(pub *PublicKey, h hashFunc, uid []byte) ([]byte, error) {
    uidLen := len(uid)
    if uidLen >= 8192 {
        return []byte{}, errors.New("cryptobin/sm2: uid too large")
    }

    entla := uint16(8 * uidLen)

    md := h()
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

func randFieldElement(random io.Reader, curve elliptic.Curve) (k *big.Int, err error) {
    if random == nil {
        // If there is no external trusted random source,
        // please use rand.Reader to instead of it.
        random = rand.Reader
    }

    params := curve.Params()

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

func intToBytes(x int) []byte {
    var buf = make([]byte, 4)
    binary.BigEndian.PutUint32(buf, uint32(x))

    return buf
}

func bigIntToBytes(curve elliptic.Curve, value *big.Int) []byte {
    byteLen := (curve.Params().BitSize + 7) / 8

    buf := make([]byte, byteLen)
    value.FillBytes(buf)

    return buf
}

func bytesToBigInt(value []byte) *big.Int {
    return new(big.Int).SetBytes(value)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}
