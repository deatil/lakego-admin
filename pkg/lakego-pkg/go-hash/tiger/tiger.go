package tiger

import (
    "hash"
)

// New returns a new hash.Hash computing the Tiger hash value
func New() hash.Hash {
    return newDigest(Size192, 1)
}

// New returns a new hash.Hash computing the Tiger2 hash value
func New2() hash.Hash {
    return newDigest(Size192, 2)
}

// ===========

// New160 returns a new hash.Hash computing the tiger160 checksum
func New160() hash.Hash {
    return newDigest(Size160, 1)
}

// New2_160 returns a new hash.Hash computing the tiger160 checksum
func New2_160() hash.Hash {
    return newDigest(Size160, 2)
}

// ===========

// New128 returns a new hash.Hash computing the tiger128 checksum
func New128() hash.Hash {
    return newDigest(Size128, 1)
}

// New2_128 returns a new hash.Hash computing the tiger128 checksum
func New2_128() hash.Hash {
    return newDigest(Size128, 2)
}
