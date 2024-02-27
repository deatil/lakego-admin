package gost34112012256

import (
    "encoding/binary"
)

var (
    TLSMagmaCTROMAC = TLSTreeParams{
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x00}),
    }

    TLSKuznyechikCTROMAC = TLSTreeParams{
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0}),
    }

    TLSKuznyechikMGML = TLSTreeParams{
        binary.BigEndian.Uint64([]byte{0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00}),
    }

    TLSMagmaMGML = TLSTreeParams{
        binary.BigEndian.Uint64([]byte{0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80}),
    }

    TLSKuznyechikMGMS = TLSTreeParams{
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8}),
    }

    TLSMagmaMGMS = TLSTreeParams{
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00}),
        binary.BigEndian.Uint64([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
    }
)

type TLSTreeParams [3]uint64

type TLSTree struct {
    params     TLSTreeParams
    keyRoot    []byte
    seqNumPrev uint64
    seq        []byte
    key        []byte
}

func NewTLSTree(params TLSTreeParams, keyRoot []byte) *TLSTree {
    key := make([]byte, len(keyRoot))
    copy(key, keyRoot)

    return &TLSTree{
        params:  params,
        keyRoot: key,
        seq:     make([]byte, 8),
        key:     make([]byte, Size),
    }
}

func (t *TLSTree) DeriveCached(seqNum uint64) ([]byte, bool) {
    if seqNum > 0 &&
        (seqNum&t.params[0]) == ((t.seqNumPrev)&t.params[0]) &&
        (seqNum&t.params[1]) == ((t.seqNumPrev)&t.params[1]) &&
        (seqNum&t.params[2]) == ((t.seqNumPrev)&t.params[2]) {
        return t.key, true
    }

    binary.BigEndian.PutUint64(t.seq, seqNum&t.params[0])
    pass1 := KDF(New, t.keyRoot, []byte("level1"), t.seq)

    binary.BigEndian.PutUint64(t.seq, seqNum&t.params[1])
    pass2 := KDF(New, pass1, []byte("level2"), t.seq)

    binary.BigEndian.PutUint64(t.seq, seqNum&t.params[2])
    pass3 := KDF(New, pass2, []byte("level3"), t.seq)

    t.seqNumPrev = seqNum

    t.key = pass3

    return t.key, false
}

func (t *TLSTree) Derive(seqNum uint64) []byte {
    key, _ := t.DeriveCached(seqNum)

    keyDerived := make([]byte, Size)
    copy(keyDerived, key)

    return keyDerived
}
