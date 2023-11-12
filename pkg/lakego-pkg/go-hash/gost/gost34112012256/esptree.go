package gost34112012256

import (
    "crypto/subtle"
)

type ESPTree struct {
    keyRoot []byte
    isPrev  [5]byte
    key     []byte
}

func NewESPTree(keyRoot []byte) *ESPTree {
    key := make([]byte, len(keyRoot))
    copy(key, keyRoot)

    t := &ESPTree{
        keyRoot: key,
        key:     make([]byte, Size),
    }

    t.isPrev[0]++
    t.DeriveCached([]byte{0x00, 0x00, 0x00, 0x00, 0x00})

    return t
}

func (t *ESPTree) DeriveCached(is []byte) ([]byte, bool) {
    if len(is) != 1+2+2 {
        panic("invalid i1+i2+i3 input")
    }

    if subtle.ConstantTimeCompare(t.isPrev[:], is) == 1 {
        return t.key, true
    }

    pass1 := KDF(New, t.keyRoot, []byte("level1"), append([]byte{0}, is[0]))
    pass2 := KDF(New, pass1, []byte("level2"), is[1:3])
    pass3 := KDF(New, pass2, []byte("level3"), is[3:5])

    copy(t.isPrev[:], is)

    t.key = pass3

    return t.key, false
}

func (t *ESPTree) Derive(is []byte) []byte {
    key, _ := t.DeriveCached(is)

    keyDerived := make([]byte, Size)
    copy(keyDerived, key)

    return keyDerived
}
