package ginga

const (
    // hash size
    Size = 32

    // hash block size
    BlockSize = 16

    // internal rounds
    internalRounds = 8
)

type digest struct {
    s   [8]uint32
    x   [BlockSize]byte
    nx  int
    len uint64
}

// newDigest returns a new *digest computing the ginga checksum
func newDigest() *digest {
    d := new(digest)
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.s = iv
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
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() (out []byte) {
    buf := make([]byte, d.nx)
    copy(buf, d.x[:d.nx])

    buf = append(buf, 0x80)
    for len(buf)%BlockSize != 8 {
        buf = append(buf, 0x00)
    }

    lenBits := d.len * 8
    lenBytes := make([]byte, 8)

    putu64(lenBytes, lenBits)
    buf = append(buf, lenBytes...)

    for len(buf) >= BlockSize {
        d.processBlock(buf[:BlockSize])
        buf = buf[BlockSize:]
    }

    out = make([]byte, Size)
    for i := 0; i < 8; i++ {
        putu32(out[i*4:], d.s[i])
    }

    return
}

func (d *digest) processBlock(block []byte) {
    var m [4]uint32
    for i := 0; i < 4; i++ {
        m[i] = getu32(block[i*4 : (i+1)*4])
    }

    // salva estado anterior
    prev := d.s

    // faz a compressão com os rounds
    for r := 0; r < internalRounds; r++ {
        for i := 0; i < 8; i++ {
            k := subKey32(m, r, i&3)
            d.s[i] = round32(d.s[i], k, r)
        }

        mixState256(&d.s)
    }

    // aplica Miyaguchi-Preneel: H = f(H, M) ⊕ M ⊕ H
    for i := 0; i < 8; i++ {
        d.s[i] ^= m[i&3] ^ prev[i]
    }
}
