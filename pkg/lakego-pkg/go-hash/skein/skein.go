// Package skein implements the Skein512 hash function
// based on the Threefish tweakable block cipher.
package skein

import "hash"

// Overview
//
// Skein is a hash function family using the tweakable block cipher
// Threefish in Unique Block Iteration (UBI) chaining mode while
// leveraging an optional low-overhead argument-system
// for flexibility. There are three versions of Skein, each of them
// using the corresponding Threefish version:
// 		- Skein256  using Threefish256  and processes 256  bit blocks
//		- Skein512  using Threefish512  and processes 512  bit blocks
//		- Skein1024 using Threefish1024 and processes 1024 bit blocks
//
// Skein can be used as hash function, MAC or KDF and supports personalized,
// randomized (salted) and public-key-bound hashing. Furthermore Skein
// has some additional features (currently) not implemented here. For
// details see http://www.skein-hash.info/
// Skein was submitted to the SHA-3 challenge.
//
// Skein can produce hash values of any size (up to (2^64 -1) x BlockSize bytes)
// not only the common sizes 160, 224, 256, 384 and 512 bit.
//
//
// Security and Recommendations
//
// All Skein varaiants (as far as known) secure. The Skein authors recommend to use
// Skein512 for most applications. Skein256 should be used for small devices
// like smartcards. Skein1024 is the ultra-conservative variant providing a level of
// security (mostly) not needed.

// Config contains the Skein configuration:
// - Key for computing MACs
// - Personal for personalized hashing
// - PublicKey for public-key-bound hashing
// - KeyID for key derivation
// - Nonce for randomized hashing
// All fields are optional and can be nil.
type Config struct {
    Key       []byte // Optional: The secret key for MAC
    Personal  []byte // Optional: The personalization for unique hashing
    PublicKey []byte // Optional: The public key for public-key bound hashing
    KeyID     []byte // Optional: The key id for key derivation
    Nonce     []byte // Optional: The nonce for randomized hashing
}

// Sum512 computes the 512 bit Skein512 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum512(msg, key []byte) (out [64]byte) {
    s := new(hashFunc)

    if len(key) > 0 {
        s.initialize(64, &Config{Key: key})
    } else {
        s.hVal = iv512
        s.hValCpy = iv512
        s.hashsize = BlockSize
        s.tweak[0] = 0
        s.tweak[1] = CfgMessage<<56 | FirstBlock
    }

    s.Write(msg)
    s.finalizeHash()

    var out512 [64]byte
    s.output(&out512, 0)

    copy(out[:], out512[:])

    return
}

// Sum384 computes the 384 bit Skein512 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum384(msg, key []byte) (out [48]byte) {
    var out512 [64]byte
    s := new(hashFunc)

    if len(key) > 0 {
        s.initialize(48, &Config{Key: key})
    } else {
        s.hVal = iv384
        s.hValCpy = iv384
        s.hashsize = 48
        s.tweak[0] = 0
        s.tweak[1] = CfgMessage<<56 | FirstBlock
    }

    s.Write(msg)

    s.finalizeHash()
    s.output(&out512, 0)

    copy(out[:], out512[:48])

    return
}

// Sum256 computes the 256 bit Skein512 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum256(msg, key []byte) (out [32]byte) {
    var out512 [64]byte
    s := new(hashFunc)

    if len(key) > 0 {
        s.initialize(32, &Config{Key: key})
    } else {
        s.hVal = iv256
        s.hValCpy = iv256
        s.hashsize = 32
        s.tweak[0] = 0
        s.tweak[1] = CfgMessage<<56 | FirstBlock
    }

    s.Write(msg)

    s.finalizeHash()
    s.output(&out512, 0)

    copy(out[:], out512[:32])

    return
}

// Sum160 computes the 160 bit Skein512 checksum (or MAC if key is set) of msg
// and writes it to out. The key is optional and can be nil.
func Sum160(msg, key []byte) (out [20]byte) {
    var out512 [64]byte
    s := new(hashFunc)

    if len(key) > 0 {
        s.initialize(20, &Config{Key: key})
    } else {
        s.hVal = iv160
        s.hValCpy = iv160
        s.hashsize = 20
        s.tweak[0] = 0
        s.tweak[1] = CfgMessage<<56 | FirstBlock
    }

    s.Write(msg)

    s.finalizeHash()
    s.output(&out512, 0)

    copy(out[:], out512[:20])

    return
}

// Sum returns the Skein512 checksum with the given hash size of msg using the (optional)
// conf for configuration. The hashsize must be > 0.
func Sum(msg []byte, hashsize int, conf *Config) []byte {
    s := New(hashsize, conf)
    s.Write(msg)
    return s.Sum(nil)
}

// New512 returns a hash.Hash computing the Skein512 512 bit checksum.
// The key is optional and turns the hash into a MAC.
func New512(key []byte) hash.Hash {
    s := new(hashFunc)

    if len(key) > 0 {
        s.initialize(BlockSize, &Config{Key: key})
    } else {
        copy(s.hVal[:8], iv512[:])
        s.hValCpy = s.hVal
        s.hashsize = BlockSize
        s.tweak[0] = 0
        s.tweak[1] = CfgMessage<<56 | FirstBlock
    }

    return s
}

// New256 returns a hash.Hash computing the Skein512 256 bit checksum.
// The key is optional and turns the hash into a MAC.
func New256(key []byte) hash.Hash {
    s := new(hashFunc)

    if len(key) > 0 {
        s.initialize(32, &Config{Key: key})
    } else {
        copy(s.hVal[:8], iv256[:])
        s.hValCpy = s.hVal
        s.hashsize = 32
        s.tweak[0] = 0
        s.tweak[1] = CfgMessage<<56 | FirstBlock
    }

    return s
}

// New returns a hash.Hash computing the Skein512 checksum with the given hash size.
// The conf is optional and configurates the hash.Hash
func New(hashsize int, conf *Config) hash.Hash {
    s := new(hashFunc)
    s.initialize(hashsize, conf)
    return s
}
