package kcdsa

import (
    "hash"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/hash/has160"
)

type ParameterSizes int

const (
    A2048B224SHA224 ParameterSizes = 1 + iota
    A2048B224SHA256
    A2048B256SHA256
    A3072B256SHA256
    A1024B160HAS160
)

func (ps ParameterSizes) Hash() hash.Hash {
    domain, ok := GetSizes(ps)
    if !ok {
        panic(msgInvalidParameterSizes)
    }

    return domain.NewHash()
}

type ParameterSize struct {
    A, B int
    LH   int
    L    int

    NewHash func() hash.Hash
}

var paramValuesMap = map[ParameterSizes]ParameterSize{
    A2048B224SHA224: {
        A:       2048,
        B:       224,
        NewHash: sha256.New224,
        LH:      sha256.Size224 * 8,
        L:       sha256.BlockSize,
    },
    A2048B224SHA256: {
        A:       2048,
        B:       224,
        NewHash: sha256.New,
        LH:      sha256.Size * 8,
        L:       sha256.BlockSize,
    },
    A2048B256SHA256: {
        A:       2048,
        B:       256,
        NewHash: sha256.New,
        LH:      sha256.Size * 8,
        L:       sha256.BlockSize,
    },
    A3072B256SHA256: {
        A:       3072,
        B:       256,
        NewHash: sha256.New,
        LH:      sha256.Size * 8,
        L:       sha256.BlockSize,
    },
    A1024B160HAS160: {
        A:       1024,
        B:       160,
        NewHash: has160.New,
        LH:      has160.Size * 8,
        L:       has160.BlockSize,
    },
}

func GetSizes(sizes ParameterSizes) (ParameterSize, bool) {
    p, ok := paramValuesMap[sizes]
    return p, ok
}
