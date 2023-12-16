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
    digest [8]uint32
    nblocks uint64
    block [BlockSize]byte
    num int
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
    this.digest[0] = 0x7380166F
    this.digest[1] = 0x4914B2B9
    this.digest[2] = 0x172442D7
    this.digest[3] = 0xDA8A0600
    this.digest[4] = 0xA96F30BC
    this.digest[5] = 0x163138AA
    this.digest[6] = 0xE38DEE4D
    this.digest[7] = 0xB0FB0E4E

    this.nblocks = 0
    this.block = [BlockSize]byte{}
    this.num = 0
}

// Write is the interface for IO Writer
func (this *digest) Write(data []byte) (nn int, err error) {
    nn = len(data)

    var blocks int

    dataLen := len(data)

    this.num &= 0x3f
    if this.num > 0 {
        var left int = BlockSize - this.num

        if dataLen < left {
            copy(this.block[this.num:], data)
            this.num += dataLen

            return
        } else {
            copy(this.block[this.num:], data[:left])
            compressBlocks(this.digest[:], this.block[:], 1)

            this.nblocks++

            data = data[left:]
            dataLen -= left
        }
    }

    blocks = dataLen / BlockSize
    if blocks > 0 {
        compressBlocks(this.digest[:], data, blocks)

        this.nblocks += uint64(blocks)

        data = data[BlockSize * blocks:]
        dataLen -= BlockSize * blocks
    }

    this.num = dataLen
    if dataLen > 0 {
        copy(this.block[:], data)
    }

    return
}

func (this *digest) Sum(in []byte) []byte {
    var i int32

    this.num &= 0x3f
    this.block[this.num] = 0x80

    if this.num <= BlockSize - 9 {
        memsetUint8(this.block[this.num + 1:BlockSize - 8], 0)
    } else {
        memsetUint8(this.block[this.num + 1:BlockSize], 0)
        compressBlocks(this.digest[:], this.block[:], 1)
        memsetUint8(this.block[:BlockSize - 8], 0)
    }

    PUTU32(this.block[56:], uint32(this.nblocks >> 23))
    PUTU32(this.block[60:], uint32((this.nblocks << 9) + uint64(this.num << 3)))

    compressBlocks(this.digest[:], this.block[:], 1)

    var digest [Size]byte
    for i = 0; i < 8; i++ {
        PUTU32(digest[i*4:], this.digest[i])
    }

    return append(in, digest[:]...)
}
