package hash

import (
    "crypto/cipher"

    "github.com/deatil/go-hash/gost/gost341194"
    "github.com/deatil/go-hash/gost/gost34112012"
    "github.com/deatil/go-hash/gost/gost34112012256"
    "github.com/deatil/go-hash/gost/gost34112012512"
)

// gost341194 签名
func (this Hash) Gost341194(cipher func([]byte) cipher.Block) Hash {
    h := gost341194.New(cipher)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewGost341194
func (this Hash) NewGost341194(cipher func([]byte) cipher.Block) Hash {
    this.hash = gost341194.New(cipher)

    return this
}

// ===============

// gost34112012 签名
func (this Hash) Gost34112012(size int) Hash {
    h := gost34112012.New(size)
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewGost34112012
func (this Hash) NewGost34112012(size int) Hash {
    this.hash = gost34112012.New(size)

    return this
}

// ===============

// gost34112012256 签名
func (this Hash) Gost34112012256() Hash {
    h := gost34112012256.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewGost34112012256
func (this Hash) NewGost34112012256() Hash {
    this.hash = gost34112012256.New()

    return this
}

// ===============

// gost34112012512 签名
func (this Hash) Gost34112012512() Hash {
    h := gost34112012512.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewGost34112012512
func (this Hash) NewGost34112012512() Hash {
    this.hash = gost34112012512.New()

    return this
}
