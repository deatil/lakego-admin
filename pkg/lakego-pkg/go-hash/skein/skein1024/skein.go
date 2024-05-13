// Package skein1024 implements the Skein1024 hash function
// based on the Threefish1024 tweakable block cipher.
package skein1024

import (
    "hash"

    "github.com/deatil/go-hash/skein"
)

// Sum512 computes the 512 bit Skein1024 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum512(msg, key []byte) (out [64]byte) {
    var out1024 [128]byte

    s := new(hashFunc)
    s.initialize(64, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out1024, 0)
    copy(out[:], out1024[:64])

    return
}

// Sum384 computes the 384 bit Skein1024 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum384(msg, key []byte) (out [48]byte) {
    var out1024 [128]byte

    s := new(hashFunc)
    s.initialize(48, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out1024, 0)
    copy(out[:], out1024[:48])

    return
}

// Sum256 computes the 256 bit Skein1024 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum256(msg, key []byte) (out [32]byte) {
    var out1024 [128]byte

    s := new(hashFunc)
    s.initialize(32, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out1024, 0)
    copy(out[:], out1024[:32])

    return
}

// Sum160 computes the 160 bit Skein1024 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum160(msg, key []byte) (out [20]byte) {
    var out1024 [128]byte

    s := new(hashFunc)
    s.initialize(20, &skein.Config{Key: key})

    s.Write(msg)

    s.finalizeHash()

    s.output(&out1024, 0)
    copy(out[:], out1024[:20])

    return
}

// Sum returns the Skein1024 checksum with the given hash size of msg using the (optional)
// conf for configuration. The hashsize must be > 0.
func Sum(msg []byte, hashsize int, conf *skein.Config) []byte {
    s := New(hashsize, conf)
    s.Write(msg)
    return s.Sum(nil)
}

// New512 returns a hash.Hash computing the Skein1024 512 bit checksum.
// The key is optional and turns the hash into a MAC.
func New512(key []byte) hash.Hash {
    s := new(hashFunc)

    s.initialize(64, &skein.Config{Key: key})

    return s
}

// New256 returns a hash.Hash computing the Skein1024 256 bit checksum.
// The key is optional and turns the hash into a MAC.
func New256(key []byte) hash.Hash {
    s := new(hashFunc)

    s.initialize(32, &skein.Config{Key: key})

    return s
}

// New returns a hash.Hash computing the Skein1024 checksum with the given hash size.
// The conf is optional and configurates the hash.Hash
func New(hashsize int, conf *skein.Config) hash.Hash {
    s := new(hashFunc)
    s.initialize(hashsize, conf)
    return s
}
