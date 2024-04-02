package tiger

import (
    "hash"
)

// digest160 represents the partial evaluation of a checksum.
type digest160 struct {
    h hash.Hash
}

// New160 returns a new hash.Hash computing the tiger160 checksum
func New160() hash.Hash {
    d := new(digest160)
    d.h = New()
    d.Reset()

    return d
}

// New2_160 returns a new hash.Hash computing the tiger160 checksum
func New2_160() hash.Hash {
    d := new(digest160)
    d.h = New2()
    d.Reset()

    return d
}

func (d *digest160) Reset() {
    d.h.Reset()
}

func (d *digest160) Size() int {
    return Size160
}

func (d *digest160) BlockSize() int {
    return BlockSize
}

func (d *digest160) Write(p []byte) (nn int, err error) {
    return d.h.Write(p)
}

func (d *digest160) Sum(in []byte) []byte {
    hash := d.h.Sum(nil)
    return append(in, hash[:Size160]...)
}
