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

type HashMac struct {
    h func() go_hash.Hash
}

func NewHashMac(h func() go_hash.Hash) IHash {
    return &HashMac{h}
}

func (this *HashMac) Size() int {
    return this.h().Size()
}

func (this *HashMac) Hash(c, k []byte) []byte {
    hash := this.h()
    hash.Write(c)
    hash.Write(k)

    return hash.Sum(nil)
}

// HmacSM3
var HmacSM3Hash = NewHashHmac(sm3.New)

// HmacSHA256
var HmacSHA256Hash = NewHashHmac(sha256.New)

// SM3Hash
var SM3Hash = NewHashMac(sm3.New)

// SHA256Hash
var SHA256Hash = NewHashMac(sha256.New)

// 默认 Hash
var DefaultHash = HmacSHA256Hash
