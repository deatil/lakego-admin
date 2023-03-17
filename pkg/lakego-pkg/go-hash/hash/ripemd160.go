package hash

import (
    "golang.org/x/crypto/ripemd160"
)

// Ripemd160 哈希值
func (this Hash) Ripemd160() Hash {
    h := ripemd160.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewRipemd160
func (this Hash) NewRipemd160() Hash {
    this.hash = ripemd160.New()

    return this
}
