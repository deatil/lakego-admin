package blake256

import "hash"

// New returns a new hash.Hash computing the BLAKE-256 checksum.
func New() hash.Hash {
    return &digest{
        hashSize: 256,
        h:        iv256,
    }
}

// NewSalt is like New but initializes salt with the given 16-byte slice.
func NewSalt(salt []byte) hash.Hash {
    d := &digest{
        hashSize: 256,
        h:        iv256,
    }
    d.setSalt(salt)
    return d
}

// New224 returns a new hash.Hash computing the BLAKE-224 checksum.
func New224() hash.Hash {
    return &digest{
        hashSize: 224,
        h:        iv224,
    }
}

// New224Salt is like New224 but initializes salt with the given 16-byte slice.
func New224Salt(salt []byte) hash.Hash {
    d := &digest{
        hashSize: 224,
        h:        iv224,
    }
    d.setSalt(salt)
    return d
}

// Sum256 returns the BLAKE-256 checksum of the data.
func Sum256(data []byte) [Size]byte {
    var d digest
    d.hashSize = 256
    d.Reset()
    d.Write(data)
    return d.checkSum()
}

// Sum224 returns the BLAKE-224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
    var d digest
    d.hashSize = 224
    d.Reset()
    d.Write(data)
    sum := d.checkSum()
    copy(sum224[:], sum[:Size224])
    return
}
