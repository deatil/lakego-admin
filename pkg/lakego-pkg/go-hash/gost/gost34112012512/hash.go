package gost34112012512

import (
    "hash"
    
    "github.com/deatil/go-hash/gost/gost34112012"
)

// GOST R 34.11-2012 512-bit hash function.
// RFC 6986. Big-endian hash output.

const (
    BlockSize = gost34112012.BlockSize
    Size      = 64
)

func New() hash.Hash {
    return gost34112012.New(64)
}
