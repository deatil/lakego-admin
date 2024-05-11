// Package skein implements the Skein-512 hash function, MAC, and stream cipher
// as defined in "The Skein Hash Function Family, v1.3".
package skein512

import (
    "hash"
    "crypto/cipher"
)

// NewHash returns hash.Hash calculating checksum of the given length in bytes
// (for example, to calculate 256-bit hash, outLen must be set to 32).
func NewHash(outLen uint64) hash.Hash {
    return hash.Hash(New(outLen, nil))
}

// NewHash224 returns a new hash.Hash computing the Skein-224 checksum
func NewHash224() hash.Hash {
    return NewHash(28)
}

// NewHash256 returns a new hash.Hash computing the Skein-256 checksum
func NewHash256() hash.Hash {
    return NewHash(32)
}

// NewHash384 returns a new hash.Hash computing the Skein-384 checksum
func NewHash384() hash.Hash {
    return NewHash(48)
}

// NewHash512 returns a new hash.Hash computing the Skein-512 checksum
func NewHash512() hash.Hash {
    return NewHash(64)
}

// NewMAC returns hash.Hash calculating Skein Message Authentication Code of the
// given length in bytes. A MAC is a cryptographic hash that uses a key to
// authenticate a message. The receiver verifies the hash by recomputing it
// using the same key.
func NewMAC(outLen uint64, key []byte) hash.Hash {
    return hash.Hash(New(outLen, &Args{Key: key}))
}

// NewStream returns a cipher.Stream for encrypting a message with the given key
// and nonce. The same key-nonce combination must not be used to encrypt more
// than one message. There are no limits on the length of key or nonce.
func NewStream(key []byte, nonce []byte) cipher.Stream {
    const streamOutLen = (1<<64 - 1) / 8 // 2^64 - 1 bits
    h := New(streamOutLen, &Args{Key: key, Nonce: nonce, NoMsg: true})
    return newOutputReader(h)
}
