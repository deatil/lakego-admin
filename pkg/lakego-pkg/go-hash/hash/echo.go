package hash

import (
    "github.com/deatil/go-hash/echo"
)

// Echo224 哈希值
func (this Hash) Echo224() Hash {
    sum := echo.Sum224(this.data)
    this.data = sum[:]

    return this
}

// NewEcho224
func (this Hash) NewEcho224() Hash {
    this.hash = echo.New224()

    return this
}

// ===========

// Echo256 哈希值
func (this Hash) Echo256() Hash {
    sum := echo.Sum256(this.data)
    this.data = sum[:]

    return this
}

// NewEcho256
func (this Hash) NewEcho256() Hash {
    this.hash = echo.New256()

    return this
}

// ===========

// Echo384 哈希值
func (this Hash) Echo384() Hash {
    sum := echo.Sum384(this.data)
    this.data = sum[:]

    return this
}

// NewEcho384
func (this Hash) NewEcho384() Hash {
    this.hash = echo.New384()

    return this
}

// ===========

// Echo512 哈希值
func (this Hash) Echo512() Hash {
    sum := echo.Sum512(this.data)
    this.data = sum[:]

    return this
}

// NewEcho512
func (this Hash) NewEcho512() Hash {
    this.hash = echo.New512()

    return this
}
