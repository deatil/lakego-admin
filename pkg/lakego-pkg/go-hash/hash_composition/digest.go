package hash_composition

import (
    "hash"
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    h1 hash.Hash
    h2 hash.Hash
}

// newDigest returns a new digest computing the hash_composition checksum
func newDigest(h1, h2 func() hash.Hash) *digest {
    d := new(digest)
    d.h1 = h1()
    d.h2 = h2()
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.h1.Reset()
    d.h2.Reset()
}

func (d *digest) Size() int {
    return d.h1.Size()
}

func (d *digest) BlockSize() int {
    return d.h1.BlockSize()
}

func (d *digest) Write(p []byte) (nn int, err error) {
    return d.h2.Write(p)
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() []byte {
    h2Digest := d.h2.Sum(nil)

    d.h1.Write(h2Digest)
    return d.h1.Sum(nil)
}
