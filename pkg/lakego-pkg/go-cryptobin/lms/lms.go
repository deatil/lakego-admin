package lms

import (
    "io"
    "errors"
    "crypto"
    "crypto/subtle"
    "encoding/binary"
)

// Signer Opts
type SignerOpts struct {
    C []byte
}

func (this SignerOpts) HashFunc() crypto.Hash {
    return crypto.Hash(0)
}

// default Signer Opts
var DefaultSignerOpts = SignerOpts{}

// A PrivateKey is used to sign a finite number of messages
type PrivateKey struct {
    PublicKey
    q        uint32
    seed     []byte
    authtree [][]byte
}

// GenerateKey returns a PrivateKey, seeded by a cryptographically secure
// random number generator.
func GenerateKey(rng io.Reader, tc ILmsParam, otstc ILmotsParam) (*PrivateKey, error) {
    params := tc.Params()

    seed := make([]byte, params.M)
    if _, err := rng.Read(seed); err != nil {
        return nil, err
    }

    idbytes := make([]byte, ID_LEN)
    if _, err := rng.Read(idbytes); err != nil {
        return nil, err
    }

    id := ID(idbytes)

    return GenerateKeyFromSeed(tc, otstc, id, seed)
}

// GenerateKeyFromSeed returns a new PrivateKey, using the algorithm from
// Appendix A of <https://datatracker.ietf.org/doc/html/rfc8554#appendix-A>
func GenerateKeyFromSeed(tc ILmsParam, otstc ILmotsParam, id ID, seed []byte) (*PrivateKey, error) {
    tree, err := GeneratePKTree(tc, otstc, id, seed)
    if err != nil {
        return nil, err
    }

    return &PrivateKey{
        PublicKey: PublicKey{
            typ:     tc,
            otsType: otstc,
            id:      id,
            k:       tree[0],
        },
        q:        0,
        seed:     seed,
        authtree: tree,
    }, nil
}

// Public returns an PublicKey that validates signatures for this private key
func (priv *PrivateKey) Public() crypto.PublicKey {
    return priv.PublicKey
}

// Sign calculates the LMS signature of a chosen message.
func (priv *PrivateKey) Sign(rng io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
    sig, err := priv.SignToSignature(rng, msg, opts)
    if err != nil {
        return nil, err
    }

    return sig.ToBytes()
}

// SignToSignature calculates the LMS signature of a chosen message.
func (priv *PrivateKey) SignToSignature(rng io.Reader, msg []byte, opts crypto.SignerOpts) (*Signature, error) {
    opt := DefaultSignerOpts
    if o, ok := opts.(SignerOpts); ok {
        opt = o
    }

    params := priv.typ.Params()

    height := int(params.H)
    var leaves uint32 = 1 << height
    if priv.q >= leaves {
        return nil, errors.New("Sign(): invalid private key")
    }

    // ots_params := ots_tc.Params()
    ots_priv, err := NewLmsOtsPrivateKeyFromSeed(priv.otsType, priv.q, priv.id, priv.seed)
    if err != nil {
        return nil, err
    }

    ots_sig, err := ots_priv.SignToSignature(rng, msg, LmsOtsSignerOpts{
        C: opt.C,
    })
    if err != nil {
        return nil, err
    }

    authpath := make([][]byte, params.H)

    var r uint32 = leaves + priv.q
    var temp uint32
    for i := 0; i < height; i++ {
        temp = (r >> i) ^ 1
        // We use x-1 because T[x] is indexed from 1, not 0, in the spec
        authpath[i] = priv.authtree[temp-1][:]
    }

    // We incremenet q to signal the this keys should not be reused
    priv.incrementQ()

    return &Signature{
        typ:  priv.typ,
        q:    priv.q - 1,
        ots:  *ots_sig,
        path: authpath,
    }, nil
}

// Private
func (priv *PrivateKey) incrementQ() {
    priv.q++
}

// ToBytes() serialized the private key into a byte string for storage.
// The current value of the internal counter, q, is included.
func (priv *PrivateKey) ToBytes() []byte {
    var serialized []byte
    var u32_be [4]byte

    // First 4 bytes: typecode
    typecode := priv.typ.GetType()

    // ToBytes() is only ever called on a valid object, so this will never return an error
    binary.BigEndian.PutUint32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next 4 bytes: OTS typecode
    otstype := priv.otsType.GetType()

    // ToBytes() is only ever called on a valid object, so this will never return an error
    binary.BigEndian.PutUint32(u32_be[:], uint32(otstype))
    serialized = append(serialized, u32_be[:]...)

    // Next 4 bytes: q
    binary.BigEndian.PutUint32(u32_be[:], priv.q)
    serialized = append(serialized, u32_be[:]...)

    // Next 16 bytes: id
    serialized = append(serialized, priv.id[:]...)

    // Next params.M bytes: seed, it can 32 bytes
    serialized = append(serialized, priv.seed[:]...)

    return serialized
}

// Retrieve the current value of the internal counter, q.
// Used for unit tests
func (priv *PrivateKey) Q() uint32 {
    return priv.q
}

// NewPrivateKeyFromBytes returns an PrivateKey that represents b.
// This is the inverse of the ToBytes() method on the PrivateKey object.
func NewPrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
    if len(b) < 8 {
        return nil, errors.New("NewPrivateKeyFromBytes(): Input is too short")
    }

    // The typecode is bytes 0-3 (4 bytes)
    newTypecode, err := GetLmsParam(LmsType(binary.BigEndian.Uint32(b[0:4])))
    if err != nil {
        return nil, err
    }

    // The OTS typecode is bytes 4-7 (4 bytes)
    newOtstype, err := GetLmotsParam(LmotsType(binary.BigEndian.Uint32(b[4:8])))
    if err != nil {
        return nil, err
    }

    typecode := newTypecode()
    otstype := newOtstype()

    lmsparams := typecode.Params()

    if len(b) < int(lmsparams.M+28) {
        return nil, errors.New("NewPrivateKeyFromBytes(): Input is too short")
    }

    // Internal counter is bytes 8-11 (4 bytes)
    q := binary.BigEndian.Uint32(b[8:12])
    // ID is bytes 12-27 (16 bytes)
    id := ID(b[12:28])

    // Seed is bytes 28+ (32 bytes for SHA-256)
    seed_end := lmsparams.M + 28
    seed := b[28:seed_end]

    // Load private key, then set q to what was persisted
    privateKey, err := GenerateKeyFromSeed(typecode, otstype, id, seed)
    if err != nil {
        return nil, err
    }

    privateKey.q = q
    return privateKey, nil
}

// GeneratePKTree generates the Merkle Tree needed to derive the public key and
// authentication path for any message.
func GeneratePKTree(tc ILmsParam, otstc ILmotsParam, id ID, seed []byte) ([][]byte, error) {
    params := tc.Params()
    ots_params := otstc.Params()

    var tree_nodes uint32 = (1 << (params.H + 1)) - 1
    var leaves uint32 = 1 << params.H
    var authtree = make([][]byte, tree_nodes)
    var i uint32
    var j uint32

    var r uint32
    var r_be [4]byte
    for i = 0; i < leaves; i++ {
        r = i + leaves
        ots_priv, err := NewLmsOtsPrivateKeyFromSeed(otstc, i, id, seed)
        if err != nil {
            return nil, err
        }

        ots_pub := ots_priv.LmsOtsPublicKey

        binary.BigEndian.PutUint32(r_be[:], r)

        hasher := ots_params.Hash()
        hasher.Write(id[:])
        hasher.Write(r_be[:])
        hasher.Write(D_LEAF[:])
        hasher.Write(ots_pub.Key())
        authtree[r-1] = hasher.Sum(nil)

        j = i
        for j%2 == 1 {
            r = (r - 1) >> 1
            j = (j - 1) >> 1

            binary.BigEndian.PutUint32(r_be[:], r)

            hasher := ots_params.Hash()
            hasher.Write(id[:])
            hasher.Write(r_be[:])
            hasher.Write(D_INTR[:])
            hasher.Write(authtree[2*r-1])
            hasher.Write(authtree[2*r])
            authtree[r-1] = hasher.Sum(nil)
        }
    }

    return authtree, nil
}

// A PublicKey is used to verify messages signed by a PrivateKey
type PublicKey struct {
    typ      ILmsParam
    otsType  ILmotsParam
    id       ID
    k        []byte
}

// NewPublicKey return a new PublicKey, given the LMS typecode, LM-OTS typecode, ID, and
// root of the authentication tree (called k).
func NewPublicKey(tc ILmsParam, otstc ILmotsParam, id ID, k []byte) (*PublicKey, error) {
    // Explicit check from Algorithm 6, Step 1 of RFC 8554
    if len(k) < 8 {
        return nil, errors.New("NewPublicKey(): invalid public key")
    }

    return &PublicKey{
        typ:     tc,
        otsType: otstc,
        id:      id,
        k:       k[:],
    }, nil
}

// Verify returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *PublicKey) Verify(msg []byte, sig []byte) bool {
    newSig, err := NewSignatureFromBytes(sig)
    if err != nil {
        return false
    }

    return pub.VerifyWithSignature(msg, newSig)
}

// VerifyWithSignature returns true if sig is valid for msg and this public key.
// It returns false otherwise.
func (pub *PublicKey) VerifyWithSignature(msg []byte, sig *Signature) bool {
    params := pub.typ.Params()
    ots_params := pub.otsType.Params()

    height := int(params.H)
    leaves := uint32(1 << height)

    key_candidate, valid := sig.ots.RecoverPublicKey(msg, pub.id, sig.q)
    if !valid {
        return false
    }

    node_num := sig.q + leaves

    var node_num_bytes [4]byte
    var tmp_be [4]byte
    binary.BigEndian.PutUint32(node_num_bytes[:], node_num)

    hasher := ots_params.Hash()
    hasher.Write(pub.id[:])
    hasher.Write(node_num_bytes[:])
    hasher.Write(D_LEAF[:])
    hasher.Write(key_candidate.Key())
    tmp := hasher.Sum(nil)

    for i := 0; i < height; i++ {
        binary.BigEndian.PutUint32(tmp_be[:], node_num>>1)

        hasher := ots_params.Hash()
        hasher.Write(pub.id[:])
        hasher.Write(tmp_be[:])
        hasher.Write(D_INTR[:])

        if node_num%2 == 1 {
            hasher.Write(sig.path[i])
            hasher.Write(tmp)
        } else {
            hasher.Write(tmp)
            hasher.Write(sig.path[i])
        }

        tmp = hasher.Sum(nil)
        node_num >>= 1
    }

    return subtle.ConstantTimeCompare(tmp, pub.k) == 1
}

// ToBytes() serializes the public key into a byte string for transmission or storage.
func (pub *PublicKey) ToBytes() []byte {
    var serialized []byte
    var u32_be [4]byte

    // First 4 bytes: typecode
    typecode := pub.typ.GetType()

    // ToBytes() is only ever called on a valid object, so this will never return an error
    binary.BigEndian.PutUint32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next 4 bytes: OTS typecode
    otstype := pub.otsType.GetType()

    // ToBytes() is only ever called on a valid object, so this will never return an error
    binary.BigEndian.PutUint32(u32_be[:], uint32(otstype))
    serialized = append(serialized, u32_be[:]...)

    // Next 16 bytes: id
    serialized = append(serialized, pub.id[:]...)

    // Followed by the public key, k
    serialized = append(serialized, pub.k[:]...)

    return serialized
}

// Return a []byte representing the actual public key, k, which is the root of the
// authentication path in the corresponding private key.
// We need this to get the public key as bytes in order to test
func (pub *PublicKey) Key() []byte {
    return pub.k[:]
}

// Return the ID for this public key
func (pub *PublicKey) ID() ID {
    return pub.id
}

// NewPublicKeyFromBytes returns an PublicKey that represents b.
// This is the inverse of the ToBytes() method on the PublicKey object.
func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
    if len(b) < 8 {
        return nil, errors.New("PublicKeyFromBytes(): key must be more than 8 bytes long")
    }

    // The typecode is bytes 0-3 (4 bytes)
    newTypecode, err := GetLmsParam(LmsType(binary.BigEndian.Uint32(b[0:4])))
    if err != nil {
        return nil, err
    }

    // The OTS typecode is bytes 4-7 (4 bytes)
    newOtstype, err := GetLmotsParam(LmotsType(binary.BigEndian.Uint32(b[4:8])))
    if err != nil {
        return nil, err
    }

    typecode := newTypecode()
    otstype := newOtstype()

    // Ensure b is the correct length
    lmsparams := typecode.Params()

    if uint64(len(b)) != lmsparams.M+24 {
        return nil, errors.New("PublicKeyFromBytes(): invalid key length")
    }

    // The ID is bytes 8-23 (16 bytes)
    id := ID(b[8:24])
    // The public key, k, is the remaining bytes
    k := b[24:]

    return &PublicKey{
        typ:     typecode,
        otsType: otstype,
        id:      id,
        k:       k,
    }, nil
}

// A Signature represents a signature produced by an PrivateKey
// which an PublicKey can validate for a given message
type Signature struct {
    typ  ILmsParam
    q    uint32
    ots  LmsOtsSignature
    path [][]byte
}

// NewSignature returns a Signature, given an LMS algorithm type, internal counter,
// LM-OTS signature, and authentication path.
func NewSignature(tc ILmsParam, q uint32, otsig LmsOtsSignature, path [][]byte) (*Signature, error) {
    params := tc.Params()

    var tmp uint32 = 1 << params.H

    // From step 2i of Algorithm 6a in RFC 8554
    if q >= tmp {
        return nil, errors.New("NewSignature(): Invalid signature")
    }

    // There should be H elements in the authpath
    if uint64(len(path)) != params.H {
        return nil, errors.New("NewSignature(): Invalid signature authentication path")
    }

    return &Signature{
        typ:  tc,
        q:    q,
        ots:  otsig,
        path: path,
    }, nil
}

// NewSignatureFromBytes returns an Signature represented by b.
// This is the inverse of the ToBytes() on Signature.
func NewSignatureFromBytes(b []byte) (*Signature, error) {
    if len(b) < 8 {
        return nil, errors.New("NewSignatureFromBytes(): Signature is too short")
    }

    var err error

    // The internal counter is bytes 0-3
    q := binary.BigEndian.Uint32(b[0:4])

    // The OTS signature starts at byte 4, with the typecode first
    newOtstc, err := GetLmotsParam(LmotsType(binary.BigEndian.Uint32(b[4:8])))
    if err != nil {
        return nil, err
    }

    otstc := newOtstc()

    // 4 + LM-OTS signature length is the first byte after the LM-OTS sig
    otsSiglen := otstc.SigLength()

    otsigmax := 4 + otsSiglen
    if uint64(4+len(b)) <= otsigmax {
        // We are only ensuring that we can read the LMS typecode
        return nil, errors.New("NewSignatureFromBytes(): Signature is too short for LM-OTS typecode")
    }

    // Now that we know we have enough bytes for LMS, look at the typecode
    newTypecode, err := GetLmsParam(LmsType(binary.BigEndian.Uint32(b[otsigmax : otsigmax+4])))
    if err != nil {
        return nil, err
    }

    typecode := newTypecode()

    // With both typecodes, we can calculate the total signature length
    siglen := typecode.SigLength(otstc)

    if siglen != uint64(len(b)) {
        return nil, errors.New("NewSignatureFromBytes(): Invalid LMS signature length")
    }

    // currenly undefined func
    otsig, err := NewLmsOtsSignatureFromBytes(b[4:otsigmax])
    if err != nil {
        return nil, err
    }

    // With the lengths and OTS sig in hand, we can now parse the LMS sig
    lmsparams := typecode.Params()

    var height = lmsparams.H
    m := lmsparams.M
    var start = otsigmax + 4

    // Explicitly check that q < 2^H
    if q >= (1 << height) {
        return nil, errors.New("NewSignatureFromBytes(): Internal counter is too high")
    }

    // Read the authentication path
    var path = make([][]byte, lmsparams.H)
    var i uint64
    for i = 0; i < height; i++ {
        end := start + m
        path[i] = b[start:end]
        start += m
    }

    return &Signature{
        typ:  typecode,
        q:    q,
        ots:  *otsig,
        path: path,
    }, nil
}

// ToBytes() serializes the signature into a byte string for transmission or storage.
func (sig *Signature) ToBytes() ([]byte, error) {
    var serialized []byte
    var u32_be [4]byte

    typecode := sig.typ.GetType()
    params := sig.typ.Params()

    // First 4 bytes: q
    binary.BigEndian.PutUint32(u32_be[:], sig.q)
    serialized = append(serialized, u32_be[:]...)

    // Encode the LM-OTS signature next
    // currenly undefined func
    ots_sig, err := sig.ots.ToBytes()
    if err != nil {
        return nil, err
    }

    serialized = append(serialized, ots_sig[:]...)

    // Next 4 bytes: LMS typecode
    binary.BigEndian.PutUint32(u32_be[:], uint32(typecode))
    serialized = append(serialized, u32_be[:]...)

    // Next M * H bytes: Path
    height := int(params.H)
    for i := 0; i < height; i++ {
        serialized = append(serialized, sig.path[i]...)
    }

    return serialized, nil
}
