package xxh3

import (
    "hash"
)

// XXH128_hash_t
type Uint128 struct {
    Low, High uint64
}

func (u Uint128) Bytes() (out [16]byte) {
    putu64be(out[0:], u.High)
    putu64be(out[8:], u.Low)

    return
}

// Hash128
type Hash128 interface {
    hash.Hash
    Sum128() Uint128
}
