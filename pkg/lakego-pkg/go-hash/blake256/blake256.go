package blake256

import "hash"

// New returns a new hash.Hash computing the BLAKE-256 checksum.
func New() hash.Hash {
    return newDigest(256, iv256)
}

// NewWithSalt is like New but initializes salt with the given 16-byte slice.
func NewWithSalt(salt []byte) hash.Hash {
    d := newDigest(256, iv256)
    d.setSalt(salt)
    return d
}

// Sum returns the BLAKE-256 checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    d := New()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// =======

// New224 returns a new hash.Hash computing the BLAKE-224 checksum.
func New224() hash.Hash {
    return newDigest(224, iv224)
}

// New224WithSalt is like New224 but initializes salt with the given 16-byte slice.
func New224WithSalt(salt []byte) hash.Hash {
    d := newDigest(224, iv224)
    d.setSalt(salt)
    return d
}

// Sum224 returns the BLAKE-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    d := New224()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}
