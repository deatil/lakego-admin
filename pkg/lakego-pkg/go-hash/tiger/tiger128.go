package tiger

import (
    "hash"
)

// digest128 represents the partial evaluation of a checksum.
type digest128 struct {
    h hash.Hash
}

// New128 returns a new hash.Hash computing the tiger128 checksum
func New128() hash.Hash {
    d := new(digest128)
    d.h = New()
    d.Reset()

    return d
}

// New2_128 returns a new hash.Hash computing the tiger128 checksum
func New2_128() hash.Hash {
    d := new(digest128)
    d.h = New2()
    d.Reset()

    return d
}

func (d *digest128) Reset() {
    d.h.Reset()
}

func (d *digest128) Size() int {
    return Size128
}

func (d *digest128) BlockSize() int {
    return BlockSize
}

func (d *digest128) Write(p []byte) (nn int, err error) {
    return d.h.Write(p)
}

func (d *digest128) Sum(in []byte) []byte {
    hash := d.h.Sum(nil)
    return append(in, hash[:Size128]...)
}
