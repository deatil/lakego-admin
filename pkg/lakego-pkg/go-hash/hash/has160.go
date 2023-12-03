package hash

import (
    "github.com/deatil/go-hash/has160"
)

// HAS160
func (this Hash) HAS160() Hash {
    h := has160.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewHAS160
func (this Hash) NewHAS160() Hash {
    this.hash = has160.New()

    return this
}
