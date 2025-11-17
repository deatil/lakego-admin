package lms

import (
    "io"
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
)

const HSS_MAX_LEVELS = 5

// A HSSPublicKey is used to verify messages signed by a HSSPrivateKey
type HSSPublicKey struct {
    Levels int
    LmsPub PublicKey
}

// Equal reports whether pub and x have the same value.
func (pub *HSSPublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*HSSPublicKey)
    if !ok {
        return false
    }

    return pub.Levels == xx.Levels &&
        pub.LmsPub.Equal(&xx.LmsPub)
}

// Verify returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *HSSPublicKey) Verify(msg []byte, sig []byte) bool {
    var i uint32
    var lms_pub *PublicKey
    var next_lms_pub *PublicKey
    var lms_sig *Signature

    if len(sig) < 4 {
        return false
    }

    num := getu32(sig[0:4])
    if num != uint32(pub.Levels - 1) {
        return false
    }

    sig = sig[4:]

    lms_pub = &pub.LmsPub

    var err error
    for i = 0; i < num; i++ {
        lms_sig, sig, err = pub.parseSignature(sig)
        if err != nil {
            return false
        }

        next_lms_pub, sig, err = pub.parsePublicKey(sig)
        if err != nil {
            return false
        }

        q := lms_sig.q
        C := lms_sig.ots.c

        pub_dgst := hssDigest(lms_pub, q, C, next_lms_pub.ToBytes())

        if !lms_pub.VerifyWithSignature(pub_dgst, lms_sig) {
            return false
        }

        lms_pub = next_lms_pub
    }

    lms_sig, err = NewSignatureFromBytes(sig)
    if err != nil {
        return false
    }

    if !lms_pub.VerifyWithSignature(msg, lms_sig) {
        return false
    }

    return true
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (pub *HSSPublicKey) ToBytes() []byte {
    var serialized []byte
    var u32_be [4]byte

    putu32(u32_be[:], uint32(pub.Levels))
    serialized = append(serialized, u32_be[:]...)

    pubBytes := pub.LmsPub.ToBytes()
    serialized = append(serialized, pubBytes...)

    return serialized
}

func (pub *HSSPublicKey) parseSignature(b []byte) (sig *Signature, other []byte, err error) {
    newOtstc, err := GetLmotsParam(LmotsType(getu32(b[4:8])))
    if err != nil {
        return nil, nil, err
    }

    otstc := newOtstc()

    otsSiglen := otstc.SigLength()

    otsigmax := 4 + otsSiglen
    if uint64(4+len(b)) <= otsigmax {
        return nil, nil, errors.New("go-cryptobin/lms: Signature is too short for LM-OTS typecode")
    }

    newTypecode, err := GetLmsParam(LmsType(getu32(b[otsigmax : otsigmax+4])))
    if err != nil {
        return nil, nil, err
    }

    typecode := newTypecode()

    siglen := typecode.SigLength(otstc)

    sigBytes := b[:siglen]
    other = b[siglen:]

    sig2, err := NewSignatureFromBytes(sigBytes)
    if err != nil {
        return nil, nil, err
    }

    return sig2, other, nil
}

func (pub *HSSPublicKey) parsePublicKey(b []byte) (pubkey *PublicKey, other []byte, err error) {
    if len(b) < 8 {
        return nil, nil, errors.New("go-cryptobin/lms: key must be more than 8 bytes long")
    }

    _, err = GetLmsParam(LmsType(getu32(b[0:4])))
    if err != nil {
        return nil, nil, err
    }

    newOtstype, err := GetLmotsParam(LmotsType(getu32(b[4:8])))
    if err != nil {
        return nil, nil, err
    }

    otstype := newOtstype()
    hasher := otstype.Params().Hash()

    pubSize := 4 + 4 + 16 + hasher.Size()

    pubBytes := b[:pubSize]
    other = b[pubSize:]

    pub2, err := NewPublicKeyFromBytes(pubBytes)
    if err != nil {
        return nil, nil, err
    }

    return pub2, other, nil
}

// NewHSSPublicKeyFromBytes returns an HSSPublicKey that represents b.
func NewHSSPublicKeyFromBytes(b []byte) (*HSSPublicKey, error) {
    if len(b) < 4 {
        return nil, errors.New("go-cryptobin/lms: key must be more than 4 bytes long")
    }

    levels := int(getu32(b[0:4]))

    pub, err := NewPublicKeyFromBytes(b[4:])
    if err != nil {
        return nil, err
    }

    return &HSSPublicKey{
        Levels: levels,
        LmsPub: *pub,
    }, nil
}

// A HSSPrivateKey is used to sign a finite number of messages
type HSSPrivateKey struct {
    HSSPublicKey
    LmsKey [5]PrivateKey
    LmsSig [4]Signature
}

// Equal reports whether priv and x have the same value.
func (priv *HSSPrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*HSSPrivateKey)
    if !ok {
        return false
    }

    var checkKey = func(x1, x2 *HSSPrivateKey) bool {
        if x1.Levels != x2.Levels {
            return false
        }

        levels := x1.Levels

        for i := 0; i < levels; i++ {
            if !x1.LmsKey[i].Equal(&x2.LmsKey[i]) {
                return false
            }
        }

        for i := 0; i < levels - 1; i++ {
            sig1, _ := x1.LmsSig[i].ToBytes()
            sig2, _ := x2.LmsSig[i].ToBytes()
            if subtle.ConstantTimeCompare(sig1, sig2) != 1 {
                 return false
            }
        }

        return true
    }

    return priv.HSSPublicKey.Equal(&xx.HSSPublicKey) &&
        checkKey(priv, xx)
}

// Public returns a crypto.PublicKey that validates signatures for this private key
func (priv *HSSPrivateKey) Public() crypto.PublicKey {
    return priv.HSSPublicKey
}

// PublicKey returns a HSSPublicKey that validates signatures for this private key
func (priv *HSSPrivateKey) PublicKey() HSSPublicKey {
    return priv.HSSPublicKey
}

// Sign calculates the LMS-HSS signature of a chosen message.
func (priv *HSSPrivateKey) Sign(rng io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
    var out []byte

    num := priv.HSSPublicKey.Levels - 1

    var numbytes [4]byte
    putu32(numbytes[:], uint32(num))

    out = append(out, numbytes[:]...)

    var i int
    for i = 0; i < num; i++ {
        sig, err := priv.LmsSig[i].ToBytes()
        if err != nil {
            return nil, err
        }

        out = append(out, sig...)

        pubBytes := priv.LmsKey[i + 1].PublicKey.ToBytes()
        out = append(out, pubBytes...)
    }

    sig2, err := priv.LmsKey[i].SignToSignature(rng, msg, nil)
    if err != nil {
        return nil, err
    }

    sig2Bytes, err := sig2.ToBytes()
    if err != nil {
        return nil, err
    }

    out = append(out, sig2Bytes...)

    return out, nil
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (priv *HSSPrivateKey) ToBytes() ([]byte, error) {
    var serialized []byte
    var u32_be [4]byte

    putu32(u32_be[:], uint32(priv.Levels))
    serialized = append(serialized, u32_be[:]...)

    for i := 0; i < priv.Levels; i++ {
        keyBytes := priv.LmsKey[i].ToBytes()
        serialized = append(serialized, keyBytes...)
    }

    for i := 0; i < priv.Levels - 1; i++ {
        sigBytes, err := priv.LmsSig[i].ToBytes()
        if err != nil {
            return nil, err
        }

        serialized = append(serialized, sigBytes...)
    }

    return serialized, nil
}

func (priv *HSSPrivateKey) parsePrivateKey(b []byte) (privkey *PrivateKey, other []byte, err error) {
    if len(b) < 8 {
        return nil, nil, errors.New("go-cryptobin/lms: key must be more than 8 bytes long")
    }

    newTc, err := GetLmsParam(LmsType(getu32(b[0:4])))
    if err != nil {
        return nil, nil, err
    }

    tc := newTc()

    privSize := 4 + 4 + 4 + 16 + tc.Params().M

    privBytes := b[:privSize]
    other = b[privSize:]

    priv2, err := NewPrivateKeyFromBytes(privBytes)
    if err != nil {
        return nil, nil, err
    }

    return priv2, other, nil
}

// NewHSSPrivateKeyFromBytes returns an HSSPrivateKey that represents b.
func NewHSSPrivateKeyFromBytes(b []byte) (*HSSPrivateKey, error) {
    if len(b) < 4 {
        return nil, errors.New("go-cryptobin/lms: key must be more than 4 bytes long")
    }

    levels := int(getu32(b[0:4]))
    b = b[4:]

    var priv HSSPrivateKey

    var err error
    var privTmp *PrivateKey
    var sigTmp *Signature

    for i := 0; i < levels; i++ {
        privTmp, b, err = priv.parsePrivateKey(b)
        if err != nil {
            return nil, err
        }

        priv.LmsKey[i] = *privTmp
    }

    for i := 0; i < levels - 1; i++ {
        sigTmp, b, err = priv.HSSPublicKey.parseSignature(b)
        if err != nil {
            return nil, err
        }

        priv.LmsSig[i] = *sigTmp
    }

    priv.HSSPublicKey = HSSPublicKey{
        Levels: levels,
        LmsPub: priv.LmsKey[0].PublicKey,
    }

    return &priv, nil
}

// HSS options
type HSSOpts struct {
    Type    ILmsParam
    OtsType ILmotsParam
}

// Default Opts
var DefaultOpts = []HSSOpts{
    HSSOpts{
        Type:    LMS_SHA256_M32_H5,
        OtsType: LMOTS_SHA256_N32_W8,
    },
    HSSOpts{
        Type:    LMS_SHA256_M32_H5,
        OtsType: LMOTS_SHA256_N32_W8,
    },
}

// GenerateHSSKey returns a new HSSPrivateKey
func GenerateHSSKey(rng io.Reader, opts []HSSOpts) (*HSSPrivateKey, error) {
    var q uint32 = 0
    var i int

    levels := len(opts)
    if (levels <= 0 || levels > HSS_MAX_LEVELS) {
        return nil, errors.New("go-cryptobin/lms: levels too large")
    }

    seed := make([]byte, 32)
    if _, err := rng.Read(seed); err != nil {
        return nil, err
    }

    idbytes := make([]byte, ID_LEN)
    if _, err := rng.Read(idbytes); err != nil {
        return nil, err
    }

    id := ID(idbytes)

    var err error
    var key HSSPrivateKey
    lmsKey, err := GenerateKeyFromSeed(opts[0].Type, opts[0].OtsType, id, seed)
    if err != nil {
        return nil, err
    }

    key.LmsKey[0] = *lmsKey

    key.HSSPublicKey.Levels = levels
    key.HSSPublicKey.LmsPub = key.LmsKey[0].PublicKey

    for i = 1; i < levels; i++ {
        idbytes := make([]byte, ID_LEN)
        if _, err := rng.Read(idbytes); err != nil {
            return nil, err
        }

        lmsKey, err = GenerateKeyFromSeed(opts[i].Type, opts[i].OtsType, ID(idbytes), seed)
        if err != nil {
            return nil, err
        }

        key.LmsKey[i] = *lmsKey

        C := make([]byte, 32)
        if _, err := rng.Read(C); err != nil {
            return nil, err
        }

        pub := key.LmsKey[i - 1].PublicKey
        nowPub := key.LmsKey[i].PublicKey
        dgst := hssDigest(&pub, q, C, nowPub.ToBytes())

        lmsSig, err := key.LmsKey[i - 1].SignToSignature(rand.Reader, dgst, SignerOpts{
            C: C,
        })
        if err != nil {
            return nil, err
        }

        key.LmsSig[i - 1] = *lmsSig
    }

    return &key, nil
}

func hssDigest(pub *PublicKey, q uint32, C []byte, data []byte) (dgst []byte) {
    otsParams := pub.otsType.Params()

    var qBytes [4]byte
    putu32(qBytes[:], q)

    hasher := otsParams.Hash()
    hasher.Write(pub.id[:])
    hasher.Write(qBytes[:])
    hasher.Write(D_MESG[:])
    hasher.Write(C)
    hasher.Write(data)
    dgst = hasher.Sum(nil)

    return
}
