package gost34112012256

import (
    "hash"

    "github.com/deatil/go-hash/gost/gost34112012"
)

// GOST R 34.11-2012 256-bit hash function.
// RFC 6986. Big-endian hash output.

const (
    Size      = 32
    BlockSize = gost34112012.BlockSize
)

func New() hash.Hash {
    return gost34112012.New(32)
}
