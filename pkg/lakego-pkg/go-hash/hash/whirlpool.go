package hash

import (
    "github.com/deatil/go-hash/whirlpool"
)

// Whirlpool
func (this Hash) Whirlpool() Hash {
    h := whirlpool.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewWhirlpool
func (this Hash) NewWhirlpool() Hash {
    this.hash = whirlpool.New()

    return this
}
