package sm9

import (
    go_hash "hash"
    "crypto/hmac"
    "crypto/sha256"

    "github.com/deatil/go-cryptobin/hash/sm3"
)

type HashHmac struct {
    h func() go_hash.Hash
}

func NewHashHmac(h func() go_hash.Hash) IHash {
    return &HashHmac{h}
}

func (this *HashHmac) Size() int {
    return this.h().Size()
}

func (this *HashHmac) Hash(c, k []byte) []byte {
    hash := hmac.New(this.h, k)
    hash.Write(c)

    return hash.Sum(nil)
}

// HmacSM3
var HmacSM3Hash = NewHashHmac(sm3.New)

// HmacSHA256
var HmacSHA256Hash = NewHashHmac(sha256.New)
