package blake256

import "hash"

// New returns a new hash.Hash computing the BLAKE-256 checksum.
func New() hash.Hash {
    return &digest{
        hs: 256,
        h:  iv256,
    }
}

// NewWithSalt is like New but initializes salt with the given 16-byte slice.
func NewWithSalt(salt []byte) hash.Hash {
    d := &digest{
        hs: 256,
        h:  iv256,
    }
    d.setSalt(salt)
    return d
}

// New224 returns a new hash.Hash computing the BLAKE-224 checksum.
func New224() hash.Hash {
    return &digest{
        hs: 224,
        h:  iv224,
    }
}

// New224WithSalt is like New224 but initializes salt with the given 16-byte slice.
func New224WithSalt(salt []byte) hash.Hash {
    d := &digest{
        hs: 224,
        h:  iv224,
    }
    d.setSalt(salt)
    return d
}

// Sum256 returns the BLAKE-256 checksum of the data.
func Sum256(data []byte) (out [Size]byte) {
    d := New()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum224 returns the BLAKE-224 checksum of the data.
func Sum224(data []byte) (out [Size224]byte) {
    d := New224()
    d.Write(data)
    sum := d.Sum(nil)

    copy(out[:], sum)
    return
}
