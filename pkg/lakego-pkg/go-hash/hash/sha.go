package hash

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
)

// SHA1 哈希值
func (this Hash) SHA1() Hash {
    h := sha1.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA1
func (this Hash) NewSHA1() Hash {
    this.hash = sha1.New()

    return this
}

// ===========

// SHA224 哈希值
func (this Hash) SHA224() Hash {
    h := sha256.New224()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA224
func (this Hash) NewSHA224() Hash {
    this.hash = sha256.New224()

    return this
}

// ===========

// SHA256 哈希值
func (this Hash) SHA256() Hash {
    h := sha256.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA256
func (this Hash) NewSHA256() Hash {
    this.hash = sha256.New()

    return this
}

// ===========

// SHA384 哈希值
func (this Hash) SHA384() Hash {
    h := sha512.New384()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA384
func (this Hash) NewSHA384() Hash {
    this.hash = sha512.New384()

    return this
}

// ===========

// SHA512 哈希值
func (this Hash) SHA512() Hash {
    h := sha512.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA512
func (this Hash) NewSHA512() Hash {
    this.hash = sha512.New()

    return this
}

// ===========

// SHA512_224 哈希值
func (this Hash) SHA512_224() Hash {
    h := sha512.New512_224()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA512_224
func (this Hash) NewSHA512_224() Hash {
    this.hash = sha512.New512_224()

    return this
}

// ===========

// SHA512_256 哈希值
func (this Hash) SHA512_256() Hash {
    h := sha512.New512_256()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSHA512_256
func (this Hash) NewSHA512_256() Hash {
    this.hash = sha512.New512_256()

    return this
}
