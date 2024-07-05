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

func (this *HashHmac) Mac(k, c []byte) []byte {
    hash := hmac.New(this.h, k)
    hash.Write(c)

    return hash.Sum(nil)
}

type HashMac struct {
    h func() go_hash.Hash
}

func NewHashMac(h func() go_hash.Hash) IHash {
    return &HashMac{h}
}

func (this *HashMac) Size() int {
    return this.h().Size()
}

func (this *HashMac) Mac(k, c []byte) []byte {
    hash := this.h()
    hash.Write(c)
    hash.Write(k)

    return hash.Sum(nil)
}

var (
    // HmacSM3
    HmacSM3Hash = NewHashHmac(sm3.New)

    // HmacSHA256
    HmacSHA256Hash = NewHashHmac(sha256.New)

    // SM3Hash
    SM3Hash = NewHashMac(sm3.New)

    // SHA256Hash
    SHA256Hash = NewHashMac(sha256.New)

    // Default Hash
    DefaultHash = SM3Hash
)
