package xmss

import (
    "bytes"
    "errors"
    "crypto"
    "crypto/rand"
    "crypto/subtle"
)

// Section 4.1.5. Algorithm 8: ltree
// Computes a leaf node from a WOTS public key using an L-tree.
// Note that this destroys the used WOTS public key.
func lTree(params *Params, leaf, seed []byte, wotsPub publicWOTS, a *address) {
    l := params.wlen
    var parentNodes uint32
    height := uint32(0)
    var idxIn, idxOut uint32
    n := uint32(params.n)

    a.setTreeHeight(height)

    for l > 1 {
        parentNodes = l >> 1
        for i := uint32(0); i < parentNodes; i++ {
            a.setTreeIndex(i)
            idxOut = i * n
            idxIn = i * 2 * n
            hashH(params, wotsPub[idxOut:idxOut+n], seed, wotsPub[idxIn:idxIn+2*n], a)
        }

        // If the row contained an odd number of nodes, the last node was not
        // hashed. Instead, we pull it up to the next layer.
        if l&1 == 1 {
            idxOut = (l >> 1) * n
            idxIn = (l - 1) * n
            copy(wotsPub[idxOut:idxOut+n], wotsPub[idxIn:idxIn+n])
            l = (l >> 1) + 1
        } else {
            l = l >> 1
        }
        height++
        a.setTreeHeight(height)
    }
    copy(leaf, wotsPub[:n])

}

// Section 4.1.10. Algorithm 13: XMSS_rootFromSig - Compute a root node from a tree signature
// Computes a root node given a leaf and an auth path
func computeRoot(params *Params, root, leaf, authPath, pubSeed []byte, leafIdx uint32, a *address) {
    n := params.n
    buf := make([]byte, 2*n)

    // If leafidx is odd (last bit = 1), current path element is a right child
    // and auth_path has to go left. Otherwise it is the other way around.
    if leafIdx&1 == 1 {
        copy(buf[n:], leaf)
        copy(buf[:n], authPath[:n])
    } else {
        copy(buf[:n], leaf)
        copy(buf[n:], authPath[:n])
    }
    authPath = authPath[n:]

    for i := uint32(0); i < params.treeHeight-1; i++ {
        a.setTreeHeight(i)
        leafIdx >>= 1
        a.setTreeIndex(leafIdx)

        // Pick the right or left neighbor, depending on parity of the node.
        if leafIdx&1 == 1 {
            hashH(params, buf[n:], pubSeed, buf, a)
            copy(buf[:n], authPath[:n])
        } else {
            hashH(params, buf[:n], pubSeed, buf, a)
            copy(buf[n:], authPath[:n])
        }

        authPath = authPath[n:]
    }

    a.setTreeHeight(params.treeHeight - 1)
    leafIdx >>= 1
    a.setTreeIndex(leafIdx)
    hashH(params, root, pubSeed, buf, a)
}

// Used for pseudo-random key generation.
// Generates the seed for the WOTS key pair at address a
// Takes n-byte prvSeed and returns n-byte seed using 32 byte address a
func getSeed(params *Params, seed, prvSeed []byte, a *address) {
    a.setChainAddr(0)
    a.setHashAddr(0)
    a.setKeyAndMask(0)

    bytes := a.toBytes()
    hashPRF(params, seed, prvSeed, bytes)
}

// Computes the leaf at a given address. First generates the WOTS key pair,
// then computes leaf using lTree. As this happens position independent, we
// only require that address encodes the right ltree-address.
func generateLeafWOTS(params *Params, leaf, prvSeed, pubSeed []byte, ltreeA, otsA *address) {
    seed := make([]byte, params.n)

    getSeed(params, seed, prvSeed, otsA)
    prv := *generatePrivate(params, seed)
    pub := *prv.generatePublic(params, pubSeed, otsA)

    lTree(params, leaf, pubSeed, pub, ltreeA)
}

// Section 4.1.6. Algorithm 9: treeHash
// For a given leaf index, computes the authentication path and the resulting
// root node using Merkle's TreeHash algorithm.
// Expects the layer and tree parts of subtree_addr to be set.
func treehash(params *Params, root, authPath, prvSeed, pubSeed []byte, leafIdx uint32, subtreeA address) {
    stack := make([]byte, int(params.treeHeight+1)*params.n)
    heights := make([]uint32, params.treeHeight+1)
    offset := uint32(0)
    n := uint32(params.n)

    var otsA, ltreeA, nodeA address
    var treeIdx uint32

    otsA.copySubtreeAddr(subtreeA)
    ltreeA.copySubtreeAddr(subtreeA)
    nodeA.copySubtreeAddr(subtreeA)

    otsA.setType(xmssAddrTypeOTS)
    ltreeA.setType(xmssAddrTypeLTREE)
    nodeA.setType(xmssAddrTypeHASHTREE)

    for i := uint32(0); i < uint32(1<<params.treeHeight); i++ {
        // Add the next leaf node to the stack.
        ltreeA.setLTreeAddr(i)
        otsA.setOTSAddr(i)
        generateLeafWOTS(params, stack[offset*n:offset*n+n], prvSeed, pubSeed, &ltreeA, &otsA)
        heights[offset] = 0

        // If this is a node we need for the auth path..
        if (leafIdx ^ 1) == i {
            copy(authPath[:n], stack[offset*n:offset*n+n])
        }
        offset++

        // While the top-most nodes are of equal height..
        for offset >= 2 && (heights[offset-1] == heights[offset-2]) {
            // Compute index of the new node, in the next layer.
            treeIdx = (i >> (heights[offset-1] + 1))

            // Hash the top-most nodes from the stack together
            // Note that tree height is the 'lower' layer, even though we use
            // the index of the new node on the 'higher' layer. This follows
            // from the fact that we address the hash function calls.
            nodeA.setTreeHeight(heights[offset-1])
            nodeA.setTreeIndex(treeIdx)
            stackIdx := (offset - 2) * n
            hashH(params, stack[stackIdx:stackIdx+n], pubSeed, stack[stackIdx:stackIdx+2*n], &nodeA)

            offset--
            // Note that the top-most node is now one layer higher
            heights[offset-1]++

            if ((leafIdx >> heights[offset-1]) ^ 1) == treeIdx {
                authIdx := heights[offset-1] * n
                stackIdx = (offset - 1) * n
                copy(authPath[authIdx:authIdx+n], stack[stackIdx:stackIdx+n])
            }
        }
    }

    copy(root, stack[:n])
}

// PublicKey key
type PublicKey struct {
    Params *Params
    Oid uint32
    X []byte
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
    xx, ok := x.(*PublicKey)
    if !ok {
        return false
    }

    return pub.Oid == xx.Oid &&
        bytes.Equal(pub.X, xx.X)
}

func (pub *PublicKey) Precompute() error {
    params, err := NewParamsWithOid(pub.Oid)
    if err != nil {
        return errors.New("publicKey precompute error")
    }

    pub.Params = params

    return nil
}

// PrivateKey key
type PrivateKey struct {
    PublicKey
    D []byte
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
    xx, ok := x.(*PrivateKey)
    if !ok {
        return false
    }

    return priv.PublicKey.Equal(xx.PublicKey) &&
        bytes.Equal(priv.D, xx.D)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
    return &priv.PublicKey
}

// Sign Section 4.1.9. Algorithm 12: XMSS_sign - Generate an XMSS signature and update the XMSS private key
// Signs a message. Returns an array containing the signature followed by the
// message and an updated secret key.
func (priv *PrivateKey) Sign(m []byte) ([]byte, error) {
    prv := priv.D

    params := priv.Params

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
    copy(signature[:params.indexBytes], prv[:params.indexBytes])

    // Increment the index in the private key
    copy(prv[:params.indexBytes], toBytes(int(idx+1), int(params.indexBytes)))

    // Compute the digest randomization value
    idxBytes := toBytes(int(idx), 32)
    hashPRF(params, signature[params.indexBytes:params.indexBytes+n], prfSeed, idxBytes)

    // Compute the message hash
    hashMsg(params, msgHash, signature[params.indexBytes:params.indexBytes+n], pubRoot, signature[params.signBytes-uint32(params.paddingLen)-3*n:], idx)
    copy(root, msgHash)

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
        copy(signature[params.indexBytes+n:params.indexBytes+n+params.wotsSignLen], wotsSign)

        // Compute the authentication path for the used WOTS leaf
        treehash(params, root, signature[params.indexBytes+n+params.wotsSignLen:params.indexBytes+n+params.wotsSignLen+params.treeHeight*n], prvSeed, pubSeed, idxLeaf, otsA)
    }

    return signature, nil
}

// GenerateKey Section 4.1.7. Algorithm 10: XMSS_keyGen - Generate an XMSS key pair
// Generates a XMSS key pair for a given parameter set.
// Format private: [(32bit) index || prvSeed || seed || pubSeed || root]
// Format public: [root || pubSeed]
func GenerateKey(oid uint32) (*PrivateKey, error) {
    var prv PrivateKey
    var pub PublicKey

    params, err := NewParamsWithOid(oid)
    if err != nil {
        return nil, err
    }

    prv.D = make([]byte, params.prvBytes)
    pub.X = make([]byte, params.pubBytes)

    n := uint32(params.n)

    authPath := make([]byte, params.treeHeight*n)

    var topTreeA address

    topTreeA.setLayerAddr(uint32(params.d) - 1)
    copy(prv.D[:params.indexBytes], make([]byte, params.indexBytes))

    // Initialize prvSeed, prfSeed and pubSeed
    rand.Read(prv.D[params.indexBytes : params.indexBytes+3*n])
    copy(pub.X[n:2*n], prv.D[params.indexBytes+2*n:params.indexBytes+3*n])

    // Compute root node of the top-most subtree
    treehash(params, pub.X, authPath, prv.D[params.indexBytes:params.indexBytes+n], pub.X[n:2*n], 0, topTreeA)
    copy(prv.D[params.indexBytes+3*n:], pub.X[:n])

    pub.Oid = oid
    pub.Params = params
    prv.PublicKey = pub

    return &prv, nil
}

// Verify Section 4.1.10. Algorithm 14: XMSS_verify - Verify an XMSS signature using the corresponding XMSS public key and a message
// Verifies a given message signature pair under a given public key.
// Note that this assumes a pk without an OID, i.e. [root || pubSeed]
func Verify(publicKey *PublicKey, m, signature []byte) (match bool) {
    pub := publicKey.X
    params := publicKey.Params

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
    hashMsg(params, msgHash, signature[params.indexBytes:params.indexBytes+n], pubRoot, m[params.signBytes-uint32(params.paddingLen)-3*n:], idx)
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

        wotsSign = signature[:params.wotsSignLen]
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
