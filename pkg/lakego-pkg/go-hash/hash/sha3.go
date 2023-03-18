package hash

import (
    "golang.org/x/crypto/sha3"
)

// SHA3_224 哈希值
func (this Hash) SHA3_224() Hash {
    h := sha3.New224()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA3_224
func (this Hash) NewSHA3_224() Hash {
    this.hash = sha3.New224()

    return this
}

// ============================================

// SHA3_256 哈希值
func (this Hash) SHA3_256() Hash {
    h := sha3.New256()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA3_256
func (this Hash) NewSHA3_256() Hash {
    this.hash = sha3.New256()

    return this
}

// ============================================

// SHA3_384 哈希值
func (this Hash) SHA3_384() Hash {
    h := sha3.New384()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA3_384
func (this Hash) NewSHA3_384() Hash {
    this.hash = sha3.New384()

    return this
}

// ============================================

// SHA3_512 哈希值
func (this Hash) SHA3_512() Hash {
    h := sha3.New512()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA3_512
func (this Hash) NewSHA3_512() Hash {
    this.hash = sha3.New512()

    return this
}
