package xmss

// Section 4.1.5. Algorithm 8: ltree
// Computes a leaf node from a WOTS public key using an L-tree.
// Note that this destroys the used WOTS public key.
func lTree(params *Params, leaf, seed []byte, wotsPub publicWOTS, a *address) {
    l := params.wlen
    var parentNodes uint32
    var height uint32 = 0
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
