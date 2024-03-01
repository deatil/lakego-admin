package hash

import (
    "github.com/deatil/go-hash/rabin"
)

// 国密 rabin 签名
func (this Hash) Rabin(polynomial uint64, window int) Hash {
    h := rabin.New(rabin.NewTable(polynomial, window))
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewRabin
func (this Hash) NewRabin(polynomial uint64, window int) Hash {
    this.hash = rabin.New(rabin.NewTable(polynomial, window))

    return this
}
