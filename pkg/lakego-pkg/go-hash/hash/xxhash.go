package hash

import (
    "github.com/cespare/xxhash/v2"
)

// xxhash 签名
func (this Hash) Xxhash() Hash {
    h := xxhash.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewXxhash
func (this Hash) NewXxhash() Hash {
    this.hash = xxhash.New()

    return this
}
