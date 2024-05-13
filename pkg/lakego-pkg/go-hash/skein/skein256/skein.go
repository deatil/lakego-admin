// Package skein256 implements the Skein256 hash function
// based on the Threefish256 tweakable block cipher.
package skein256

import (
    "hash"

    "github.com/deatil/go-hash/skein"
)

// Sum512 computes the 512 bit Skein256 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum512(msg, key []byte) (out [64]byte) {
    var out256 [32]byte

    s := new(hashFunc)
    s.initialize(64, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out256, 0)
    copy(out[:], out256[:])

    s.output(&out256, 1)
    copy(out[32:], out256[:])

    return
}

// Sum384 computes the 384 bit Skein256 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum384(msg, key []byte) (out [48]byte) {
    var out256 [32]byte

    s := new(hashFunc)
    s.initialize(48, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out256, 0)
    copy(out[:], out256[:])

    s.output(&out256, 1)
    copy(out[32:], out256[:16])

    return
}

// Sum256 computes the 256 bit Skein256 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum256(msg, key []byte) (out [32]byte) {
    var out256 [32]byte

    s := new(hashFunc)
    s.initialize(32, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out256, 0)
    copy(out[:], out256[:])

    return
}

// Sum160 computes the 160 bit Skein256 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum160(msg, key []byte) (out [20]byte) {
    var out256 [32]byte
    s := new(hashFunc)
    s.initialize(20, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out256, 0)
    copy(out[:], out256[:20])

    return
}

// Sum returns the Skein256 checksum with the given hash size of msg using the (optional)
// conf for configuration. The hashsize must be > 0.
func Sum(msg []byte, hashsize int, conf *skein.Config) []byte {
    s := New(hashsize, conf)
    s.Write(msg)
    return s.Sum(nil)
}

// New512 returns a hash.Hash computing the Skein256 512 bit checksum.
// The key is optional and turns the hash into a MAC.
func New512(key []byte) hash.Hash {
    s := new(hashFunc)

    s.initialize(64, &skein.Config{Key: key})

    return s
}

// New256 returns a hash.Hash computing the Skein256 256 bit checksum.
// The key is optional and turns the hash into a MAC.
func New256(key []byte) hash.Hash {
    s := new(hashFunc)

    s.initialize(32, &skein.Config{Key: key})

    return s
}

// New returns a hash.Hash computing the Skein256 checksum with the given hash size.
// The conf is optional and configurates the hash.Hash
func New(hashsize int, conf *skein.Config) hash.Hash {
    s := new(hashFunc)
    s.initialize(hashsize, conf)
    return s
}
