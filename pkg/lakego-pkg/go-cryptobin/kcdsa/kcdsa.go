package kcdsa

import (
    "io"
    "hash"
    "errors"
    "crypto"
    "math/big"
    "crypto/subtle"

    "golang.org/x/crypto/cryptobyte"
    "golang.org/x/crypto/cryptobyte/asn1"
)

// TTAK.KO-12.0001/R4

var (
    msgInvalidPublicKey            = "go-cryptobin/kcdsa: invalid public key"
    msgInvalidGenerationParameters = "go-cryptobin/kcdsa: invalid generation parameters"
    msgInvalidParameterSizes       = "go-cryptobin/kcdsa: invalid ParameterSizes"
    msgErrorParametersNotSetUp     = "go-cryptobin/kcdsa: parameters not set up before generating key"
    msgErrorShortXKEY              = "go-cryptobin/kcdsa: XKEY is too small."
    msgInvalidInteger              = "go-cryptobin/kcdsa: invalid integer"
    msgInvalidASN1                 = "go-cryptobin/kcdsa: invalid ASN.1"
    msgInvalidSignerOpts           = "go-cryptobin/kcdsa: opts must be *kcdsa.SignerOpts"
)

const NumMRTests = 64

var (
    One   = big.NewInt(1)
    Two   = big.NewInt(2)
    Three = big.NewInt(3)
)

type Hasher = func() hash.Hash

// SignerOpts contains options for creating and verifying EC-KCDSA signatures.
type SignerOpts struct {
    Hash Hasher
}

// HashFunc returns crypto.Hash
func (opts *SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// GetHash returns func() hash.Hash
func (opts *SignerOpts) GetHash() Hasher {
    return opts.Hash
}

type GenerationParameters struct {
    J     *big.Int
    Seed  []byte
    Count int
}

func (params *GenerationParameters) IsValid() bool {
    return params.Count > 0 &&
        len(params.Seed) > 0 &&
        params.J != nil &&
        params.J.Sign() > 0
}

// Equal reports whether p, q, g and sizes have the same value.
func (params *GenerationParameters) Equal(xx GenerationParameters) bool {
    return bigIntEqual(params.J, xx.J) &&
        subtle.ConstantTimeEq(int32(params.Count), int32(xx.Count)) == 1 &&
        subtle.ConstantTimeCompare(params.Seed, xx.Seed) == 1
}

type Parameters struct {
    P, Q, G *big.Int

    GenParameters GenerationParameters
}

// Equal reports whether p, q, g and sizes have the same value.
func (params Parameters) Equal(xx Parameters) bool {
    return bigIntEqual(params.P, xx.P) &&
        bigIntEqual(params.Q, xx.Q) &&
        bigIntEqual(params.G, xx.G)
}

// PublicKey represents a KCDSA public key.
type PublicKey struct {
    Parameters
    Y *big.Int
}

// Equal reports whether pub and y have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.Parameters.Equal(xx.Parameters) &&
        bigIntEqual(pub.Y, xx.Y)
}

func (pub *PublicKey) Verify(hash, sig []byte, opts crypto.SignerOpts) (bool, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return false, errors.New(msgInvalidSignerOpts)
    }

    return VerifyASN1(pub, opt.GetHash(), hash, sig), nil
}

// PrivateKey represents a KCDSA private key.
type PrivateKey struct {
    PublicKey
    X *big.Int
}

// Public returns the public key corresponding to priv.
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
        bigIntEqual(priv.X, xx.X)
}

// crypto.Signer
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    opt, ok := opts.(*SignerOpts)
    if !ok {
        return nil, errors.New(msgInvalidSignerOpts)
    }

    return SignASN1(rand, priv, opt.GetHash(), digest)
}

// Generate the parameters without Key Generation Parameters (J, Seed, Count)
func GenerateParameters(params *Parameters, rand io.Reader, sizes ParameterSizes) (err error) {
    d, ok := GetSizes(sizes)
    if !ok {
        return errors.New(msgInvalidParameterSizes)
    }

    generated, err := GenerateParametersFast(rand, d)
    if err != nil {
        return err
    }

    params.P = generated.P
    params.Q = generated.Q
    params.G = generated.G

    return
}

// Generate the parameters using Key Generation Parameters (J, Seed, Count)
func GenerateParametersTTAK(params *Parameters, rand io.Reader, sizes ParameterSizes) (err error) {
    domain, ok := GetSizes(sizes)
    if !ok {
        return errors.New(msgInvalidParameterSizes)
    }

    generated, err := generateParametersTTAK(rand, domain)
    if err != nil {
        return err
    }

    params.P = generated.P
    params.Q = generated.Q
    params.G = generated.G
    params.GenParameters.J = generated.J
    params.GenParameters.Seed = generated.Seed
    params.GenParameters.Count = generated.Count
    return
}

// TTAKParameters -> P, Q, G(randomly)
func RegenerateParameters(params *Parameters, rand io.Reader, sizes ParameterSizes) error {
    domain, ok := GetSizes(sizes)
    if !ok {
        return errors.New(msgInvalidParameterSizes)
    }

    if params.GenParameters.Count == 0 || len(params.GenParameters.Seed) == 0 {
        return errors.New(msgInvalidGenerationParameters)
    }
    if params.GenParameters.J == nil || params.GenParameters.J.Sign() <= 0 {
        return errors.New(msgInvalidGenerationParameters)
    }

    if len(params.GenParameters.Seed) != bitsToBytes(domain.B) {
        return errors.New(msgInvalidGenerationParameters)
    }

    P, Q, ok := RegeneratePQ(
        domain,
        params.GenParameters.J,
        params.GenParameters.Seed,
        params.GenParameters.Count,
    )
    if !ok {
        return errors.New(msgInvalidGenerationParameters)
    }

    H, G := new(big.Int), new(big.Int)
    _, err := GenerateHG(H, G, nil, rand, P, params.GenParameters.J)
    if err != nil {
        return err
    }

    params.P = P
    params.Q = Q
    params.G = G

    return nil
}

func GenerateKey(priv *PrivateKey, rand io.Reader) error {
    if priv.P == nil || priv.Q == nil || priv.G == nil {
        return errors.New(msgErrorParametersNotSetUp)
    }

    X, Y := new(big.Int), new(big.Int)

    XBytes := make([]byte, bitsToBytes(priv.Q.BitLen()))

    for {
        _, err := io.ReadFull(rand, XBytes)
        if err != nil {
            return err
        }
        X.SetBytes(XBytes)
        if X.Sign() > 0 && X.Cmp(priv.Q) < 0 {
            break
        }
    }
    GenerateY(Y, priv.P, priv.Q, priv.G, X)

    priv.Y = Y
    priv.X = X

    return nil
}

func GenerateKeyWithSeed(priv *PrivateKey, rand io.Reader, xkey, upri []byte, sizes ParameterSizes) (xkeyOut, upriOut []byte, err error) {
    domain, ok := GetSizes(sizes)
    if !ok {
        return nil, nil, errors.New(msgInvalidParameterSizes)
    }

    if priv.P == nil || priv.Q == nil || priv.G == nil {
        return nil, nil, errors.New(msgErrorParametersNotSetUp)
    }

    if len(xkey) == 0 {
        xkey, err = ReadBits(nil, rand, domain.B)
        if err != nil {
            return nil, nil, err
        }
    } else if len(xkey) < bitsToBytes(domain.B) {
        return nil, nil, errors.New(msgErrorShortXKEY)
    }
    if len(upri) == 0 {
        upri, err = ReadBytes(nil, rand, 64)
        if err != nil {
            return nil, nil, err
        }
    }

    h := domain.NewHash()

    priv.X, priv.Y = new(big.Int), new(big.Int)
    GenerateX(priv.X, priv.Q, upri, xkey, h, domain)
    GenerateY(priv.Y, priv.P, priv.Q, priv.G, priv.X)

    return xkey, upri, nil
}

func Sign(rand io.Reader, priv *PrivateKey, h Hasher, data []byte) (r, s *big.Int, err error) {
    if priv.Q.Sign() <= 0 || priv.P.Sign() <= 0 || priv.G.Sign() <= 0 || priv.X.Sign() <= 0 || priv.Q.BitLen()%8 != 0 {
        return nil, nil, errors.New(msgInvalidPublicKey)
    }

    r, s = new(big.Int), new(big.Int)

    qblen := priv.Q.BitLen()

    K := new(big.Int)
    buf := make([]byte, bitsToBytes(qblen))

    tmpInt := new(big.Int)
    var tmpBuf []byte

    var attempts int
    var ok bool
    for attempts = 10; attempts > 0; attempts-- {
        for {
            buf, err = ReadBits(buf, rand, qblen)
            if err != nil {
                return
            }
            K.SetBytes(buf)
            K.Add(K, One)

            if K.Sign() > 0 && K.Cmp(priv.Q) < 0 {
                break
            }
        }

        tmpBuf, ok = sign(
            r, s,
            priv,
            h,
            K, data,
            tmpInt,
            tmpBuf,
        )
        if ok {
            break
        }
    }

    // Only degenerate private keys will require more than a handful of
    // attempts.
    if attempts == 0 {
        return nil, nil, errors.New(msgInvalidPublicKey)
    }

    return
}

func Verify(pub *PublicKey, h Hasher, data []byte, r, s *big.Int) bool {
    if pub.P.Sign() <= 0 {
        return false
    }

    if r.Sign() < 1 {
        return false
    }
    if s.Sign() < 1 || s.Cmp(pub.Q) >= 0 {
        return false
    }

    return verify(pub, h, data, r, s)
}

// Sign data returns the ASN.1 encoded signature.
func SignASN1(rand io.Reader, priv *PrivateKey, h Hasher, data []byte) (sig []byte, err error) {
    r, s, err := Sign(rand, priv, h, data)
    if err != nil {
        return nil, err
    }

    return encodeSignature(r, s)
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, M, of hash using the
// public key, pub. Its return value records whether the signature is valid.
func VerifyASN1(pub *PublicKey, h Hasher, data []byte, sig []byte) bool {
    r, s, err := parseSignature(sig)
    if err != nil {
        return false
    }

    return Verify(
        pub,
        h,
        data,
        r,
        s,
    )
}

/*
P-KCDSASignatureValue ::= SEQUENCE {
    r BIT STRING,
    s INTEGER }
*/
func encodeSignature(r, s *big.Int) ([]byte, error) {
    var b cryptobyte.Builder
    b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
        b.AddASN1BigInt(r)
        b.AddASN1BigInt(s)
    })

    return b.Bytes()
}

func parseSignature(sig []byte) (r, s *big.Int, err error) {
    var inner cryptobyte.String
    input := cryptobyte.String(sig)

    r = new(big.Int)
    s = new(big.Int)

    if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
        !input.Empty() ||
        !inner.ReadASN1Integer(r) ||
        !inner.ReadASN1Integer(s) ||
        !inner.Empty() {
        return nil, nil, errors.New(msgInvalidASN1)
    }

    return
}

func sign(
    R, S *big.Int,
    priv *PrivateKey,
    hasher Hasher,
    K *big.Int,
    data []byte,
    tmpInt *big.Int,
    tmpBuf []byte,
) (tmpBufOut []byte, ok bool) {
    h := hasher()

    P, Q, G, Y, X := priv.P, priv.Q, priv.G, priv.Y, priv.X

    B := priv.Q.BitLen()
    A := priv.P.BitLen()

    l := h.BlockSize()

    tmpBuf = Grow(tmpBuf, bitsToBytes(A))

    W := tmpInt.Exp(G, K, P)
    WBytes := tmpBuf[:bitsToBytes(A)]
    W.FillBytes(WBytes)

    h.Reset()
    h.Write(WBytes)
    RBytes := RightMost(h.Sum(tmpBuf[:0]), B)
    R.SetBytes(RBytes)

    ZBytesLen := bitsToBytes(Y.BitLen())
    if ZBytesLen < l {
        ZBytesLen = l
    }
    ZBytes := tmpBuf[:ZBytesLen]
    Y.FillBytes(ZBytes)
    ZBytes = RightMost(ZBytes, l*8)

    h.Reset()
    h.Write(ZBytes)
    h.Write(data)
    HBytes := RightMost(h.Sum(tmpBuf[:0]), B)
    H := tmpInt.SetBytes(HBytes)

    E := tmpInt.Xor(R, H)
    E.Mod(E, Q)

    K.Mod(K.Sub(K, E), Q)
    S.Mul(X, K)
    S.Mod(S, Q)

    return tmpBuf, R.Sign() != 0 && S.Sign() != 0
}

func verify(
    pub *PublicKey,
    hasher Hasher,
    data []byte,
    R, S *big.Int,
) bool {
    h := hasher()

    P, Q, G, Y := pub.P, pub.Q, pub.G, pub.Y

    B := pub.Q.BitLen()
    l := h.BlockSize()

    tmpSize := l
    YBytesLen := bitsToBytes(Y.BitLen())
    PBytesLen := bitsToBytes(P.BitLen())
    if tmpSize < YBytesLen {
        tmpSize = YBytesLen
    }
    if tmpSize < PBytesLen {
        tmpSize = PBytesLen
    }

    tmp := make([]byte, tmpSize)

    tmpInt1 := new(big.Int)
    tmpInt2 := new(big.Int)

    if YBytesLen < l {
        YBytesLen = l
    }
    ZBytes := tmp[:YBytesLen]
    Y.FillBytes(ZBytes)
    ZBytes = RightMost(ZBytes, l*8)

    h.Reset()
    h.Write(ZBytes)
    h.Write(data)
    HBytes := RightMost(h.Sum(tmp[:0]), B)
    H := tmpInt1.SetBytes(HBytes)

    E := tmpInt1.Xor(R, H)
    E.Mod(E, Q)

    W := tmpInt2.Exp(Y, S, P)
    E.Exp(G, E, P)
    W.Mul(W, E)
    W.Mod(W, P)

    WBytes := tmp[:PBytesLen]
    W.FillBytes(WBytes)

    h.Reset()
    h.Write(WBytes)
    rBytes := RightMost(h.Sum(tmp[:0]), B)
    r := tmpInt1.SetBytes(rBytes)

    return bigIntEqual(R, r)
}
