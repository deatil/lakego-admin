package kupyna

import (
    "hash"
)

// The size of an kupyna384 checksum in bytes.
const Size384 = 48

// The blocksize of kupyna384 in bytes.
const BlockSize384 = 128

// digest384 represents the partial evaluation of a checksum.
type digest384 struct {
    h hash.Hash
}

// New384 returns a new hash.Hash computing the Kupyna384 checksum
func New384() hash.Hash {
    d := new(digest384)
    d.h = New512()
    d.Reset()

    return d
}

func (d *digest384) Reset() {
    d.h.Reset()
}

func (d *digest384) Size() int {
    return Size384
}

func (d *digest384) BlockSize() int {
    return BlockSize384
}

func (d *digest384) Write(p []byte) (nn int, err error) {
    return d.h.Write(p)
}

func (d *digest384) Sum(in []byte) []byte {
    hash := d.h.Sum(nil)
    return append(in, hash[16:]...)
}
