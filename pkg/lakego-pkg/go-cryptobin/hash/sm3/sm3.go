package sm3

import (
    "hash"
)

// The size of an SM3 checksum in bytes.
const Size = 32

// The blocksize of SM3 in bytes.
const BlockSize = 64

// Sum returns the SM3 checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [8]uint32
    x   [BlockSize]byte
    nx  uint64
    len int
}

// New returns a new hash.Hash computing the MD2 checksum.
func New() hash.Hash {
    d := new(digest)
    d.Reset()
    return d
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.s[0] = 0x7380166F
    this.s[1] = 0x4914B2B9
    this.s[2] = 0x172442D7
    this.s[3] = 0xDA8A0600
    this.s[4] = 0xA96F30BC
    this.s[5] = 0x163138AA
    this.s[6] = 0xE38DEE4D
    this.s[7] = 0xB0FB0E4E

    this.x = [BlockSize]byte{}
    this.nx = 0
    this.len = 0
}

// Write is the interface for IO Writer
func (this *digest) Write(data []byte) (nn int, err error) {
    nn = len(data)

    var blocks int

    dataLen := len(data)

    this.len &= 0x3f
    if this.len > 0 {
        var left int = BlockSize - this.len

        if dataLen < left {
            copy(this.x[this.len:], data)
            this.len += dataLen

            return
        } else {
            copy(this.x[this.len:], data[:left])
            compressBlocks(this.s[:], this.x[:], 1)

            this.nx++

            data = data[left:]
            dataLen -= left
        }
    }

    blocks = dataLen / BlockSize
    if blocks > 0 {
        compressBlocks(this.s[:], data, blocks)

        this.nx += uint64(blocks)

        data = data[BlockSize * blocks:]
        dataLen -= BlockSize * blocks
    }

    this.len = dataLen
    if dataLen > 0 {
        copy(this.x[:], data)
    }

    return
}

func (this *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d := *this
    hash := d.checkSum()
    return append(in, hash[:]...)
}

func (this *digest) checkSum() [Size]byte {
    var i int32

    this.len &= 0x3f
    this.x[this.len] = 0x80

    zeros := make([]byte, BlockSize)

    if this.len <= BlockSize - 9 {
        copy(this.x[this.len + 1:BlockSize - 8], zeros)
    } else {
        copy(this.x[this.len + 1:BlockSize], zeros)
        compressBlocks(this.s[:], this.x[:], 1)
        copy(this.x[:BlockSize - 8], zeros)
    }

    PUTU32(this.x[56:], uint32(this.nx >> 23))
    PUTU32(this.x[60:], uint32((this.nx << 9) + uint64(this.len << 3)))

    compressBlocks(this.s[:], this.x[:], 1)

    var digest [Size]byte
    for i = 0; i < 8; i++ {
        PUTU32(digest[i*4:], this.s[i])
    }

    return digest
}
