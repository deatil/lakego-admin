package xmss

/**
 OTC address                     L-tree addrress                 Hash Tree address
 +-------------------------+     +-------------------------+     +-------------------------+
 | layer address  (32 bits)|     | layer address  (32 bits)|     | layer address  (32 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 | tree address   (64 bits)|     | tree address   (64 bits)|     | tree address   (64 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 | type = 0       (32 bits)|     | type = 1       (32 bits)|     | type = 2       (32 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 | OTS address    (32 bits)|     | L-tree address (32 bits)|     | Padding = 0    (32 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 | chain address  (32 bits)|     | tree height    (32 bits)|     | tree height    (32 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 | hash address   (32 bits)|     | tree index     (32 bits)|     | tree index     (32 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 | keyAndMask     (32 bits)|     | keyAndMask     (32 bits)|     | keyAndMask     (32 bits)|
 +-------------------------+     +-------------------------+     +-------------------------+
 */

const (
    xmssAddrTypeOTS      = 0
    xmssAddrTypeLTREE    = 1
    xmssAddrTypeHASHTREE = 2
)

type address [8]uint32

func (a *address) setLayerAddr(layer uint32) {
    a[0] = layer
}

func (a *address) setTreeAddr(tree uint64) {
    a[1] = uint32(tree >> 32)
    a[2] = uint32(tree)
}

func (a *address) setType(typ uint32) {
    a[3] = typ
}

func (a *address) setKeyAndMask(keyMask uint32) {
    a[7] = keyMask
}

func (a *address) copySubtreeAddr(b address) {
    a[0] = b[0]
    a[1] = b[1]
    a[2] = b[2]
}

func (a *address) setOTSAddr(ots uint32) {
    a[4] = ots
}

func (a *address) setChainAddr(chain uint32) {
    a[5] = chain
}

func (a *address) setHashAddr(hash uint32) {
    a[6] = hash
}

func (a *address) setLTreeAddr(ltree uint32) {
    a[4] = ltree
}

func (a *address) setTreeHeight(h uint32) {
    a[5] = h
}

func (a *address) setTreeIndex(idx uint32) {
    a[6] = idx
}

func (a *address) toBytes() (out []byte) {
    out = make([]byte, len(a)*4)

    for i := 0; i < 8; i++ {
        copy(out[i*4:], uint32ToBytes(a[i]))
    }

    return
}
