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

func (d *digest) Reset() {
    d.s = iv
    d.x = [BlockSize]byte{}

    d.len = 0
    d.nx = 0
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) BlockSize() int {
    return BlockSize
}

// Write is the interface for IO Writer
func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    d.nx &= 0x3f

    plen := len(p)
    for d.nx + plen >= BlockSize {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x[:])

        xx := BlockSize - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (d *digest) checkSum() [Size]byte {
    d.nx &= 0x3f
    d.x[d.nx] = 0x80

    zeros := make([]byte, BlockSize)
    copy(d.x[d.nx + 1:], zeros)

    if BlockSize - d.nx < 9 {
        d.processBlock(d.x[:])
        copy(d.x[:], zeros)
    }

    bcount := d.len / BlockSize

    PUTU32(d.x[56:], uint32(bcount >> 23))
    PUTU32(d.x[60:], uint32((bcount << 9) + (uint64(d.nx) << 3)))

    d.processBlock(d.x[:])

    var digest [Size]byte
    for i := 0; i < 8; i++ {
        PUTU32(digest[i*4:], d.s[i])
    }

    return digest
}

func (d *digest) processBlock(data []byte) {
    block(d, data)
}
