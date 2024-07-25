package sm3

// The size of an SM3 checksum in bytes.
const Size = 32

// The blocksize of SM3 in bytes.
const BlockSize = 64

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [8]uint32
    x   [BlockSize]byte
    nx  int
    len uint64
}

func newDigest() *digest {
    d := new(digest)
    d.Reset()
    return d
}

func (this *digest) Reset() {
    this.s = iv
    this.x = [BlockSize]byte{}

    this.len = 0
    this.nx = 0
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

// Write is the interface for IO Writer
func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    this.len += uint64(nn)

    this.nx &= 0x3f

    plen := len(p)
    for this.nx + plen >= BlockSize {
        copy(this.x[this.nx:], p)

        this.processBlock(this.x[:])

        xx := BlockSize - this.nx
        plen -= xx

        p = p[xx:]
        this.nx = 0
    }

    copy(this.x[this.nx:], p)
    this.nx += plen

    return
}

func (this *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d := *this
    sum := d.checkSum()
    return append(in, sum[:]...)
}

func (this *digest) checkSum() [Size]byte {
    this.nx &= 0x3f
    this.x[this.nx] = 0x80

    zeros := make([]byte, BlockSize)
    copy(this.x[this.nx + 1:], zeros)

    if BlockSize - this.nx < 9 {
        this.processBlock(this.x[:])
        copy(this.x[:], zeros)
    }

    bcount := this.len / BlockSize

    PUTU32(this.x[56:], uint32(bcount >> 23))
    PUTU32(this.x[60:], uint32((bcount << 9) + (uint64(this.nx) << 3)))

    this.processBlock(this.x[:])

    var digest [Size]byte
    for i := 0; i < 8; i++ {
        PUTU32(digest[i*4:], this.s[i])
    }

    return digest
}

func (this *digest) processBlock(data []byte) {
    compressBlock(this.s[:], data)
}
