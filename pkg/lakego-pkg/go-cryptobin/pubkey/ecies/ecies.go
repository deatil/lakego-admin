package ecies

import (
    "io"
    "fmt"
    "hash"
    "math/big"
    "crypto"
    "crypto/aes"
    "crypto/ecdsa"
    "crypto/cipher"
    "crypto/elliptic"
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

var (
    ErrInvalidCurve               = fmt.Errorf("ecies: invalid elliptic curve")
    ErrInvalidParams              = fmt.Errorf("ecies: invalid ECIES parameters")
    ErrInvalidPublicKey           = fmt.Errorf("ecies: invalid public key")
    ErrInvalidPrivateKey          = fmt.Errorf("ecies: invalid private key")
    ErrSharedKeyIsPointAtInfinity = fmt.Errorf("ecies: shared key is point at infinity")
    ErrSharedKeyTooBig            = fmt.Errorf("ecies: shared key params are too big")
    ErrUnsupportedECIESParameters = fmt.Errorf("ecies: unsupported ECIES parameters")

    ErrKeyDataTooLong = fmt.Errorf("ecies: can't supply requested key data")
    ErrSharedTooLong  = fmt.Errorf("ecies: shared secret is too long")
    ErrInvalidMessage = fmt.Errorf("ecies: invalid message")
)

type ECIESParams struct {
    Hash      func() hash.Hash                   // hash function
    Cipher    func([]byte) (cipher.Block, error) // symmetric cipher
    BlockSize int                                // block size of symmetric cipher
    KeyLen    int                                // length of symmetric key
}

var (
    ECIES_AES128_SHA256 = &ECIESParams{
        Hash:      sha256.New,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    16,
    }
    ECIES_AES192_SHA384 = &ECIESParams{
        Hash:      sha512.New384,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    24,
    }
    ECIES_AES256_SHA256 = &ECIESParams{
        Hash:      sha256.New,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    32,
    }
    ECIES_AES256_SHA384 = &ECIESParams{
        Hash:      sha512.New384,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    32,
    }
    ECIES_AES256_SHA512 = &ECIESParams{
        Hash:      sha512.New,
        Cipher:    aes.NewCipher,
        BlockSize: aes.BlockSize,
        KeyLen:    32,
    }
)

// curve list
var paramsFromCurve = map[elliptic.Curve]*ECIESParams{
    secp256k1.S256(): ECIES_AES128_SHA256,
    elliptic.P256():  ECIES_AES128_SHA256,
    elliptic.P384():  ECIES_AES192_SHA384,
    elliptic.P521():  ECIES_AES256_SHA512,
}

func ParamsFromCurve(curve elliptic.Curve) *ECIESParams {
    return paramsFromCurve[curve]
}

func AddParamsFromCurve(curve elliptic.Curve, ecie *ECIESParams) {
    paramsFromCurve[curve] = ecie
}

// PublicKey is a representation of an elliptic curve public key.
type PublicKey struct {
    X *big.Int
    Y *big.Int
    elliptic.Curve
    Params *ECIESParams
}

// Export an ECIES public key as an ECDSA public key.
func (pub *PublicKey) ExportECDSA() *ecdsa.PublicKey {
    return &ecdsa.PublicKey{
        Curve: pub.Curve,
        X:     pub.X,
        Y:     pub.Y,
    }
}

// Import an ECDSA public key as an ECIES public key.
func ImportECDSAPublicKey(pub *ecdsa.PublicKey) *PublicKey {
    return &PublicKey{
        X:      pub.X,
        Y:      pub.Y,
        Curve:  pub.Curve,
        Params: ParamsFromCurve(pub.Curve),
    }
}

// PrivateKey is a representation of an elliptic curve private key.
type PrivateKey struct {
    PublicKey
    D *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Export an ECIES private key as an ECDSA private key.
func (priv *PrivateKey) ExportECDSA() *ecdsa.PrivateKey {
    pub := &priv.PublicKey

    pubECDSA := pub.ExportECDSA()

    return &ecdsa.PrivateKey{
        PublicKey: *pubECDSA,
        D:         priv.D,
    }
}

// Import an ECDSA private key as an ECIES private key.
func ImportECDSAPrivateKey(priv *ecdsa.PrivateKey) *PrivateKey {
    pub := ImportECDSAPublicKey(&priv.PublicKey)

    return &PrivateKey{
        PublicKey: *pub,
        D:         priv.D,
    }
}

// Generate an elliptic curve public / private keypair. If params is nil,
// the recommended default parameters for the key will be chosen.
func GenerateKey(rand io.Reader, curve elliptic.Curve, params *ECIESParams) (priv *PrivateKey, err error) {
    pb, x, y, err := elliptic.GenerateKey(curve, rand)
    if err != nil {
        return
    }

    priv = new(PrivateKey)
    priv.PublicKey.X = x
    priv.PublicKey.Y = y
    priv.PublicKey.Curve = curve
    priv.D = new(big.Int).SetBytes(pb)

    if params == nil {
        params = ParamsFromCurve(curve)
    }

    priv.PublicKey.Params = params
    return
}

// MaxSharedKeyLength returns the maximum length of the shared key the
// public key can produce.
func MaxSharedKeyLength(pub *PublicKey) int {
    return (pub.Curve.Params().BitSize + 7) / 8
}

// ECDH key agreement method used to establish secret keys for encryption.
func (priv *PrivateKey) GenerateShared(pub *PublicKey, skLen, macLen int) (sk []byte, err error) {
    if priv.PublicKey.Curve != pub.Curve {
        return nil, ErrInvalidCurve
    }

    if skLen + macLen > MaxSharedKeyLength(pub) {
        return nil, ErrSharedKeyTooBig
    }

    x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
    if x == nil {
        return nil, ErrSharedKeyIsPointAtInfinity
    }

    xBytes := x.Bytes()

    sk = make([]byte, skLen + macLen)

    if len(xBytes) > len(sk) {
        // copy xBytes last data to sk
        copy(sk, xBytes[len(xBytes)-len(sk):])
    } else {
        copy(sk[len(sk)-len(xBytes):], xBytes)
    }

    return sk, nil
}

// Decrypt decrypts an ECIES ciphertext.
func (priv *PrivateKey) Decrypt(c, s1, s2 []byte) (m []byte, err error) {
    if len(c) == 0 {
        err = ErrInvalidMessage
        return
    }

    // params
    params := priv.PublicKey.Params
    if params == nil {
        params = ParamsFromCurve(priv.PublicKey.Curve)
    }

    if params == nil {
        err = ErrUnsupportedECIESParameters
        return
    }

    hash := params.Hash()

    var (
        rLen   int
        hLen   int = hash.Size()
        mStart int
        mEnd   int
    )

    // 算出公钥数据长度 / get rLen
    switch c[0] {
        case 2, 3, 4:
            byteLen := (priv.PublicKey.Curve.Params().BitSize + 7) / 8

            rLen = 1 + 2*byteLen
            if len(c) < (rLen + hLen + 1) {
                err = ErrInvalidMessage
                return
            }
        default:
            err = ErrInvalidMessage
            return
    }

    mStart = rLen
    mEnd = len(c) - hLen

    // 算出公钥 / make publickey
    R := new(PublicKey)
    R.Curve = priv.PublicKey.Curve
    R.X, R.Y = elliptic.Unmarshal(R.Curve, c[:rLen])
    if R.X == nil {
        err = ErrInvalidPublicKey
        return
    }

    if !R.Curve.IsOnCurve(R.X, R.Y) {
        err = ErrInvalidCurve
        return
    }

    // 根据私钥和公钥算出密钥 / make sym key
    z, err := priv.GenerateShared(R, params.KeyLen, params.KeyLen)
    if err != nil {
        return
    }

    // kdf 方式算出密钥 / get K
    K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
    if err != nil {
        return
    }

    // 对称加密密钥 / get Ke
    Ke := K[:params.KeyLen]

    // 签名密钥 / mac key
    Km := K[params.KeyLen:]
    hash.Write(Km)
    Km = hash.Sum(nil)
    hash.Reset()

    // hmac 签名数据验证 / mac
    d := messageTag(params.Hash, Km, c[mStart:mEnd], s2)
    if subtle.ConstantTimeCompare(c[mEnd:], d) != 1 {
        err = ErrInvalidMessage
        return
    }

    // 对称加密解出数据 / decrypt data
    m, err = symDecrypt(params, Ke, c[mStart:mEnd])

    return
}

// =================================

// Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1.
//
// s1 and s2 contain shared information that is not part of the resulting
// ciphertext. s1 is fed into key derivation, s2 is fed into the MAC. If the
// shared information parameters aren't being used, they should be nil.
func Encrypt(rand io.Reader, pub *PublicKey, m, s1, s2 []byte) (ct []byte, err error) {
    params := pub.Params
    if params == nil {
        params = ParamsFromCurve(pub.Curve)
    }

    if params == nil {
        err = ErrUnsupportedECIESParameters
        return
    }

    // 生成私钥 / get R
    R, err := GenerateKey(rand, pub.Curve, params)
    if err != nil {
        return
    }

    // 根据私钥和公钥生成密钥 / make sym key
    z, err := R.GenerateShared(pub, params.KeyLen, params.KeyLen)
    if err != nil {
        return
    }

    hash := params.Hash()

    // kdf 方式算出密钥 / get K
    K, err := concatKDF(hash, z, s1, params.KeyLen+params.KeyLen)
    if err != nil {
        return
    }

    // 对称加密密钥 / get Ke
    Ke := K[:params.KeyLen]

    // 签名密钥 / get Km
    Km := K[params.KeyLen:]
    hash.Write(Km)
    Km = hash.Sum(nil)
    hash.Reset()

    // 对称加密数据 / Encrypt data
    em, err := symEncrypt(rand, params, Ke, m)
    if err != nil || len(em) <= params.BlockSize {
        return
    }

    // hmac 签名数据 / get hmac data
    d := messageTag(params.Hash, Km, em, s2)

    // 生成公钥数据 / get publickey
    Rb := elliptic.Marshal(pub.Curve, R.PublicKey.X, R.PublicKey.Y)

    // 最终数据包括 [公钥数据 + 对称加密后的数据 + hmac签名数据]
    // make ct
    ct = make([]byte, len(Rb)+len(em)+len(d))

    // 添加公钥数据 / put Rb
    copy(ct, Rb)

    // 添加对称加密后的数据 / put em
    copy(ct[len(Rb):], em)

    // 添加 hmac 签名数据 / put hmac data
    copy(ct[len(Rb)+len(em):], d)

    return
}

func Decrypt(priv *PrivateKey, c, s1, s2 []byte) (m []byte, err error) {
    if priv == nil {
        err = ErrInvalidPrivateKey
        return
    }

    return priv.Decrypt(c, s1, s2)
}

var (
    big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
    big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

func incCounter(ctr []byte) {
    if ctr[3]++; ctr[3] != 0 {
        return
    }
    if ctr[2]++; ctr[2] != 0 {
        return
    }
    if ctr[1]++; ctr[1] != 0 {
        return
    }
    if ctr[0]++; ctr[0] != 0 {
        return
    }
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) (k []byte, err error) {
    if s1 == nil {
        s1 = make([]byte, 0)
    }

    reps := ((kdLen + 7) * 8) / (hash.BlockSize() * 8)
    if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
        return nil, ErrKeyDataTooLong
    }

    counter := []byte{0, 0, 0, 1}
    k = make([]byte, 0)

    for i := 0; i <= reps; i++ {
        hash.Write(counter)
        hash.Write(z)
        hash.Write(s1)
        k = append(k, hash.Sum(nil)...)
        hash.Reset()
        incCounter(counter)
    }

    k = k[:kdLen]
    return
}

// messageTag computes the MAC of a message (called the tag) as per
// SEC 1, 3.5.
func messageTag(hash func() hash.Hash, km, msg, shared []byte) []byte {
    mac := hmac.New(hash, km)
    mac.Write(msg)
    mac.Write(shared)
    tag := mac.Sum(nil)
    return tag
}

// Generate an initialisation vector for CTR mode.
func generateIV(rand io.Reader, params *ECIESParams) (iv []byte, err error) {
    iv = make([]byte, params.BlockSize)
    _, err = io.ReadFull(rand, iv)
    return
}

// symEncrypt carries out CTR encryption using the block cipher specified in the
// parameters.
func symEncrypt(rand io.Reader, params *ECIESParams, key, m []byte) (ct []byte, err error) {
    c, err := params.Cipher(key)
    if err != nil {
        return
    }

    iv, err := generateIV(rand, params)
    if err != nil {
        return
    }

    ctr := cipher.NewCTR(c, iv)

    ct = make([]byte, len(m)+params.BlockSize)
    copy(ct, iv)

    ctr.XORKeyStream(ct[params.BlockSize:], m)

    return
}

// symDecrypt carries out CTR decryption using the block cipher specified in
// the parameters
func symDecrypt(params *ECIESParams, key, ct []byte) (m []byte, err error) {
    c, err := params.Cipher(key)
    if err != nil {
        return
    }

    ctr := cipher.NewCTR(c, ct[:params.BlockSize])

    m = make([]byte, len(ct)-params.BlockSize)
    ctr.XORKeyStream(m, ct[params.BlockSize:])

    return
}

