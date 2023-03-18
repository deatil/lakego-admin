package hash

import (
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/blake2s"
)

// Blake2b_256 哈希值
func (this Hash) Blake2b_256() Hash {
    sum := blake2b.Sum256(this.data)
    this.data = sum[:]

    return this
}

// NewBlake2b_256
func (this Hash) NewBlake2b_256(key []byte) Hash {
    this.hash, this.Error = blake2b.New256(key)

    return this
}

// ===========

// Blake2b_384 哈希值
func (this Hash) Blake2b_384() Hash {
    sum := blake2b.Sum384(this.data)
    this.data = sum[:]

    return this
}

// NewBlake2b_384
func (this Hash) NewBlake2b_384(key []byte) Hash {
    this.hash, this.Error = blake2b.New384(key)

    return this
}

// ===========

// Blake2b_512 哈希值
func (this Hash) Blake2b_512() Hash {
    sum := blake2b.Sum512(this.data)
    this.data = sum[:]

    return this
}

// NewBlake2b_512
func (this Hash) NewBlake2b_512(key []byte) Hash {
    this.hash, this.Error = blake2b.New512(key)

    return this
}

// ===========

// Blake2s_256 哈希值
func (this Hash) Blake2s_256() Hash {
    sum := blake2s.Sum256(this.data)
    this.data = sum[:]

    return this
}

// NewBlake2s_256
func (this Hash) NewBlake2s_256(key []byte) Hash {
    this.hash, this.Error = blake2s.New256(key)

    return this
}

// ===========

// Blake2s_128 哈希值
func (this Hash) Blake2s_128() Hash {
    h, err := blake2s.New128(nil)
    if err != nil {
        this.Error = err
        return this
    }

    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewBlake2s_128
func (this Hash) NewBlake2s_128(key []byte) Hash {
    this.hash, this.Error = blake2s.New128(key)

    return this
}
