package hash

import (
    "hash/fnv"
)

// Fnv32
func (this Hash) Fnv32() Hash {
    h := fnv.New32()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewFnv32
func (this Hash) NewFnv32() Hash {
    this.hash = fnv.New32()

    return this
}

// ============================================

// Fnv32a
func (this Hash) Fnv32a() Hash {
    h := fnv.New32a()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewFnv32a
func (this Hash) NewFnv32a() Hash {
    this.hash = fnv.New32a()

    return this
}

// ============================================

// Fnv64
func (this Hash) Fnv64() Hash {
    h := fnv.New64()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewFnv64
func (this Hash) NewFnv64() Hash {
    this.hash = fnv.New64()

    return this
}

// ============================================

// Fnv64a
func (this Hash) Fnv64a() Hash {
    h := fnv.New64a()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewFnv64a
func (this Hash) NewFnv64a() Hash {
    this.hash = fnv.New64a()

    return this
}

// ============================================

// Fnv128
func (this Hash) Fnv128() Hash {
    h := fnv.New128()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewFnv128
func (this Hash) NewFnv128() Hash {
    this.hash = fnv.New128()

    return this
}

// ============================================

// Fnv128a
func (this Hash) Fnv128a() Hash {
    h := fnv.New128a()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewFnv128a
func (this Hash) NewFnv128a() Hash {
    this.hash = fnv.New128a()

    return this
}
