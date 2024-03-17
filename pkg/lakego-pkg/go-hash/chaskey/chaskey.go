// Package chaskey implements the Chaskey MAC
package chaskey

import (
    "fmt"
    "hash"
    "encoding/binary"
)

/*

http://mouha.be/chaskey/

https://eprint.iacr.org/2014/386.pdf
https://eprint.iacr.org/2015/1182.pdf

*/

// The size of an chaskey checksum in bytes.
const Size = 16

// The blocksize of chaskey in bytes.
const BlockSize = 16

const KeySize   = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-hash/chaskey: invalid key size %d", int(k))
}

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [4]uint32
    k1  [4]uint32
    k2  [4]uint32
    r   int
    x   [BlockSize]byte
    nx  int
    len uint64
}

// New returns a new hash.Hash computing the chaskey checksum
// New returns a new 8-round chaskey hasher.
func New(key []byte) (hash.Hash, error) {
    return newDigest(key, 8)
}

// New12 returns a new 12-round chaskey hasher.
func New12(key []byte) (hash.Hash, error) {
    return newDigest(key, 12)
}

func newDigest(key []byte, rounds int) (hash.Hash, error) {
    l := len(key)
    if l != KeySize {
        return nil, KeySizeError(l)
    }

    var k [4]uint32

    k[0] = binary.LittleEndian.Uint32(key[0:])
    k[1] = binary.LittleEndian.Uint32(key[4:])
    k[2] = binary.LittleEndian.Uint32(key[8:])
    k[3] = binary.LittleEndian.Uint32(key[12:])

    d := new(digest)
    d.Reset()

    d.s = k
    d.r = rounds

    timestwo(d.k1[:], k[:])
    timestwo(d.k2[:], d.k1[:])

    return d, nil
}

func (d *digest) Reset() {
    d.s = [4]uint32{}
    d.k1 = [4]uint32{}
    d.k2 = [4]uint32{}
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)
    if d.nx > 0 {
        n := copy(d.x[d.nx:], p)
        d.nx += n
        if d.nx == BlockSize {
            block(d, d.x[:])
            d.nx = 0
        }

        p = p[n:]
    }

    for ; len(p) > BlockSize; p = p[BlockSize:] {
        block(d, p)
        d.nx = 0
    }

    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
    lastblock(d)

    if d.nx != 0 {
        panic("d.nx != 0")
    }

    var digest [Size]byte
    binary.LittleEndian.PutUint32(digest[0:], d.s[0])
    binary.LittleEndian.PutUint32(digest[4:], d.s[1])
    binary.LittleEndian.PutUint32(digest[8:], d.s[2])
    binary.LittleEndian.PutUint32(digest[12:], d.s[3])
    return digest
}
