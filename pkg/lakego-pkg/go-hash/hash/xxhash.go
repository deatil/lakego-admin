package hash

import (
    "github.com/deatil/go-hash/xxhash/xxhash32"
    "github.com/deatil/go-hash/xxhash/xxhash64"
)

// xxhash32 签名
func (this Hash) Xxhash32() Hash {
    h := xxhash32.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewXxhash32
func (this Hash) NewXxhash32() Hash {
    this.hash = xxhash32.New()

    return this
}

// ========

// xxhash64 签名
func (this Hash) Xxhash64() Hash {
    h := xxhash64.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewXxhash64
func (this Hash) NewXxhash64() Hash {
    this.hash = xxhash64.New()

    return this
}
