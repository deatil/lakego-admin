package xmss

import (
    "io"
    "fmt"
    "bytes"
    "errors"
    "crypto"
    "crypto/subtle"
)

// PublicKey key
type PublicKey struct {
    X []byte
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return bytes.Equal(pub.X, xx.X)
}

// PrivateKey key
type PrivateKey struct {
    D []byte
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return bytes.Equal(priv.D, xx.D)
}

func (priv *PrivateKey) PublicKey(params *Params) *PublicKey {
    n := uint32(params.n)
    x := make([]byte, 2*n)

    copy(x[:n], priv.D[params.indexBytes+3*n:params.indexBytes+4*n])
    copy(x[n:], priv.D[params.indexBytes+2*n:params.indexBytes+3*n])

    return &PublicKey{
        X: x,
    }
}

// Sign Section 4.1.9. Algorithm 12: XMSS_sign - Generate an XMSS signature and update the XMSS private key
// Signs a message. Returns an array containing the signature followed by the
// message and an updated secret key.
func (priv *PrivateKey) Sign(params *Params, m []byte) ([]byte, error) {
    if params == nil {
        return nil, errors.New("xmss: Params error")
    }

    prv := priv.D

    var signature []byte
    signature = make([]byte, int(params.signBytes)+len(m))

    n := uint32(params.n)
    prvSeed := prv[params.indexBytes : params.indexBytes+n]
    prfSeed := prv[params.indexBytes+n : params.indexBytes+2*n]
    pubSeed := prv[params.indexBytes+2*n : params.indexBytes+3*n]
    pubRoot := prv[params.indexBytes+3*n : params.indexBytes+4*n]

    root := make([]byte, n)
    msgHash := make([]byte, n)
    otsSeed := make([]byte, n)
    var idxLeaf uint32

    var otsA address
    otsA.setType(xmssAddrTypeOTS)

    // Already put the message in the right place, to make it easier to prepend
    // things when computing the hash over the message
    copy(signature[params.signBytes:], m)

    idx := fromBytes(prv[:params.indexBytes], int(params.indexBytes))

    if idx >= ((1 << params.fullHeight) - 1) {
        memsetByte(prv[:params.indexBytes], 0xFF)
        memsetByte(prv[params.indexBytes:(params.prvBytes - params.indexBytes)], 0)
        if idx > ((1 << params.fullHeight) - 1) {
            return nil, errors.New("xmss: fullHeight is error")
        }

        if (params.fullHeight == 64) && (idx == ((1 << params.fullHeight) - 1)) {
            return nil, errors.New("xmss: fullHeight is long")
        }
    }

    copy(signature[:params.indexBytes], prv[:params.indexBytes])

    // Increment the index in the private key
    copy(prv[:params.indexBytes], toBytes(int(idx+1), int(params.indexBytes)))

    // Compute the digest randomization value
    idxBytes := toBytes(int(idx), 32)
    hashPRF(params, signature[params.indexBytes:params.indexBytes+n], prfSeed, idxBytes)

    // Compute the message hash
    hashMsg(params, msgHash, signature[params.indexBytes:params.indexBytes+n], pubRoot, signature[params.signBytes-uint32(params.paddingLen)-3*n:], idx)
    copy(root, msgHash)

    var buf bytes.Buffer
    for i := uint32(0); i < uint32(params.d); i++ {
        idxLeaf = uint32(idx) & ((1 << params.treeHeight) - 1)
        idx = idx >> params.treeHeight

        otsA.setLayerAddr(i)
        otsA.setTreeAddr(idx)
        otsA.setOTSAddr(idxLeaf)

        // Get a seed for the WOTS keypair
        getSeed(params, otsSeed, prvSeed, &otsA)

        wotsPrv := *generatePrivate(params, otsSeed)
        wotsSign := *wotsPrv.sign(params, root, pubSeed, &otsA)

        buf.Write(wotsSign)

        // Compute the authentication path for the used WOTS leaf
        treehashData := make([]byte, params.treeHeight*n)
        treehash(params, root, treehashData, prvSeed, pubSeed, idxLeaf, otsA)

        buf.Write(treehashData)
    }

    copy(signature[params.indexBytes+n:], buf.Bytes())

    return signature, nil
}

// GenerateKey Section 4.1.7. Algorithm 10: XMSS_keyGen - Generate an XMSS key pair
// Generates a XMSS key pair for a given parameter set.
// Format private: [(32bit) index || prvSeed || seed || pubSeed || root]
// Format public: [root || pubSeed]
func GenerateKey(rand io.Reader, params *Params) (*PrivateKey, *PublicKey, error) {
    if params == nil {
        return nil, nil, errors.New("xmss: Params error")
    }

    var prv PrivateKey
    var pub PublicKey

    prv.D = make([]byte, params.prvBytes)
    pub.X = make([]byte, params.pubBytes)

    n := uint32(params.n)

    authPath := make([]byte, params.treeHeight*n)

    var topTreeA address

    topTreeA.setLayerAddr(uint32(params.d) - 1)
    copy(prv.D[:params.indexBytes], make([]byte, params.indexBytes))

    // Initialize prvSeed, prfSeed and pubSeed
    seed := make([]byte, 3*n)
    if _, err := io.ReadFull(rand, seed); err != nil {
        return nil, nil, fmt.Errorf("xmss: %w", err)
    }

    copy(prv.D[params.indexBytes:], seed)
    copy(pub.X[n:2*n], prv.D[params.indexBytes+2*n:params.indexBytes+3*n])

    // Compute root node of the top-most subtree
    treehash(params, pub.X, authPath, prv.D[params.indexBytes:params.indexBytes+n], pub.X[n:2*n], 0, topTreeA)
    copy(prv.D[params.indexBytes+3*n:], pub.X[:n])

    return &prv, &pub, nil
}

// Verify Section 4.1.10. Algorithm 14:
// XMSS_verify - Verify an XMSS signature using the corresponding XMSS public key and a message
// Verifies a given message signature pair under a given public key.
// Note that this assumes a pk without an OID, i.e. [root || pubSeed]
func Verify(params *Params, publicKey *PublicKey, m, signature []byte) (match bool) {
    if params == nil {
        return false
    }

    if len(signature) < int(params.signBytes) {
        return false
    }

    pub := publicKey.X

    n := uint32(params.n)

    pubRoot := pub[:n]
    pubSeed := pub[n:]

    var wotsSign signatureWOTS
    var wotsPub publicWOTS

    leaf := make([]byte, n)
    root := make([]byte, n)
    msgHash := make([]byte, n)
    msgLen := len(signature) - int(params.signBytes)

    var otsA, ltreeA, nodeA address
    otsA.setType(xmssAddrTypeOTS)
    ltreeA.setType(xmssAddrTypeLTREE)
    nodeA.setType(xmssAddrTypeHASHTREE)

    idx := fromBytes(signature[:params.indexBytes], int(params.indexBytes))

    copy(m[params.signBytes:], signature[params.signBytes:])

    hashMsg(
        params, msgHash,
        signature[params.indexBytes:params.indexBytes+n],
        pubRoot,
        m[params.signBytes-uint32(params.paddingLen)-3*n:],
        idx,
    )
    copy(root, msgHash)

    signature = signature[params.indexBytes+n:]

    for i := uint32(0); i < uint32(params.d); i++ {
        idxLeaf := (uint32(idx) & ((1 << params.treeHeight) - 1))
        idx = idx >> params.treeHeight

        otsA.setLayerAddr(i)
        ltreeA.setLayerAddr(i)
        nodeA.setLayerAddr(i)

        ltreeA.setTreeAddr(idx)
        otsA.setTreeAddr(idx)
        nodeA.setTreeAddr(idx)

        // The WOTS public key is only correct if the signature was correct
        otsA.setOTSAddr(idxLeaf)

        wotsSign = signatureWOTS(signature[:params.wotsSignLen])

        // Initially, root = mhash, but on subsequent iterations it is the root
        // of the subtree below the currently processed subtree.
        wotsPub = *wotsSign.getPublic(params, root, pubSeed, &otsA)
        signature = signature[params.wotsSignLen:]

        // Compute the leaf node using the WOTS public key
        ltreeA.setLTreeAddr(idxLeaf)
        lTree(params, leaf, pubSeed, wotsPub, &ltreeA)

        // Compute the root node of this subtree
        computeRoot(params, root, leaf, signature[:params.treeHeight*n], pubSeed, idxLeaf, &nodeA)
        signature = signature[params.treeHeight*n:]
    }

    // Check if the root node equals the root node in the public key
    if subtle.ConstantTimeCompare(root, pubRoot) == 0 {
        // Zero the message
        copy(m[params.signBytes:], make([]byte, msgLen))
        match = false
    } else {
        copy(m[params.signBytes:], signature)
        match = true
    }

    return
}
