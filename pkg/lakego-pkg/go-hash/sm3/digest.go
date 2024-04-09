package sm3

// The size of an SM3 checksum in bytes.
const Size = 32

// The blocksize of SM3 in bytes.
const BlockSize = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [8]uint32
    x   [BlockSize]byte
    nx  uint64
    len int
}

func newDigest() *digest {
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
    this.s = iv
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
    sum := d.checkSum()
    return append(in, sum[:]...)
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
