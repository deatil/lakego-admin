package blake512

import "hash"

// New returns a new hash.Hash computing the BLAKE-512 checksum.
func New() hash.Hash {
    return newDigest(64, iv512)
}

// NewWithSalt is like New but initializes salt with the given 32-byte slice.
func NewWithSalt(salt []byte) hash.Hash {
    d := newDigest(64, iv512)
    d.setSalt(salt)
    return d
}

// New384 returns a new hash.Hash computing the BLAKE-384 checksum.
func New384() hash.Hash {
    return newDigest(48, iv384)
}

// New384WithSalt is like New384 but initializes salt with the given 32-byte slice.
func New384WithSalt(salt []byte) hash.Hash {
    d := newDigest(48, iv384)
    d.setSalt(salt)
    return d
}

// Sum returns the BLAKE-512 checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    d := New()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum384 returns the BLAKE-384 checksum of the data.
func Sum384(data []byte) (out [Size384]byte) {
    d := New384()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}
