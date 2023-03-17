package hash

import (
    "hash/adler32"
)

// Adler32
func (this Hash) Adler32() Hash {
    h := adler32.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewAdler32
func (this Hash) NewAdler32() Hash {
    this.hash = adler32.New()

    return this
}
