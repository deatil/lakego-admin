package hash

import (
    "io"
    "hash"
)

// Write
func (this Hash) Write(p []byte) Hash {
    this.hash.Write(p)

    return this
}

// WriteString
func (this Hash) WriteString(s string) Hash {
    p := []byte(s)
    this.hash.Write(p)

    return this
}

// WriteReader
func (this Hash) WriteReader(reader io.Reader) Hash {
    h := this.hash

    _, err := io.Copy(h, reader)
    if err != nil {
        this.Error = err

        return this
    }

    this.hash = h

    return this
}

// Sum
func (this Hash) Sum(in []byte) Hash {
    this.data = this.hash.Sum(in)

    return this
}

// Sum32
func (this Hash) Sum32() uint32 {
    if hash32, ok := this.hash.(hash.Hash32); ok {
        return hash32.Sum32()
    }

    return 0
}

// Sum64
func (this Hash) Sum64() uint64 {
    if hash64, ok := this.hash.(hash.Hash64); ok {
        return hash64.Sum64()
    }

    return 0
}

// Reset
func (this Hash) Reset() Hash {
    this.hash.Reset()

    return this
}

// Size
func (this Hash) Size() int {
    return this.hash.Size()
}

// BlockSize
func (this Hash) BlockSize() int {
    return this.hash.BlockSize()
}

// Hash
func (this Hash) Hash() hash.Hash {
    return this.hash
}
