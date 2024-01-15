package hash

import (
    "hash"

    "golang.org/x/crypto/sha3"
)

var newShake128 = func() hash.Hash {
    return sha3.NewShake128()
}

var newShake256 = func() hash.Hash {
    return sha3.NewShake256()
}

var newCShake128 = func(N, S []byte) hash.Hash {
    return sha3.NewCShake128(N, S)
}

var newCShake256 = func(N, S []byte) hash.Hash {
    return sha3.NewCShake256(N, S)
}

// ===========

// Shake128 哈希值 num = 64
func (this Hash) Shake128(num int) Hash {
    data := make([]byte, num)
    sha3.ShakeSum128(data, this.data)

    this.data = data

    return this
}

// NewShake128
func (this Hash) NewShake128() Hash {
    this.hash = newShake128()

    return this
}

// ===========

// Shake256 哈希值 num = 64
func (this Hash) Shake256(num int) Hash {
    data := make([]byte, num)
    sha3.ShakeSum256(data, this.data)

    this.data = data

    return this
}

// NewShake256
func (this Hash) NewShake256() Hash {
    this.hash = newShake256()

    return this
}

// ===========

// CShake128 哈希值 num = 64
func (this Hash) CShake128(N, S []byte, num int) Hash {
    h := sha3.NewCShake128(N, S)
    h.Write(this.data)

    hash := make([]byte, num)
    h.Read(hash)

    this.data = hash

    return this
}

// NewCShake128
func (this Hash) NewCShake128(N, S []byte) Hash {
    this.hash = newCShake128(N, S)

    return this
}

// ===========

// CShake256 哈希值 num = 64
func (this Hash) CShake256(N, S []byte, num int) Hash {
    h := sha3.NewCShake256(N, S)
    h.Write(this.data)

    hash := make([]byte, num)
    h.Read(hash)

    this.data = hash

    return this
}

// NewCShake256
func (this Hash) NewCShake256(N, S []byte) Hash {
    this.hash = newCShake256(N, S)

    return this
}
