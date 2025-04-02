package belt

const (
    // hash size
    Size = 32

    // block size
    BlockSize = 32
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [32]byte
    x   [32]byte
    nx  int
    len uint64

    h [32]byte
}

// newDigest returns a new digest computing the belt checksum
func newDigest() *digest {
    d := new(digest)
    d.Reset()

    return d
}

func (d *digest) Reset() {
    d.s = [32]byte{}
    d.x = [32]byte{}
    d.nx = 0
    d.len = 0

    copy(d.h[:], uint64sToBytes(iv))
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

        d.processBlock(d.x)

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

func (d *digest) checkSum() []byte {
    if d.nx != 0 {
        /* Pad our last block with zeroes */
        zeros := make([]byte, 32)
        copy(d.x[d.nx:], zeros)

        /* Update the counter with the remaining data */
        d.updateCtr(d.nx)

        /* Process the last block */
        d.hashProcess(d.x)
    }

    /* Finalize and output the result */
    var out [32]byte
    hashFinalize(d.s, d.h, &out)

    return out[:]
}

func (d *digest) processBlock(data [BELT_HASH_BLOCK_SIZE]byte) {
    /* Update the counter with one full block */
    d.updateCtr(BELT_HASH_BLOCK_SIZE)

    /* Process */
    d.hashProcess(data)
}

func (d *digest) hashProcess(data [BELT_HASH_BLOCK_SIZE]byte) {
    s := [BELT_BLOCK_LEN]byte{}
    copy(s[:], d.s[BELT_BLOCK_LEN:])

    hashProcess(data, &d.h, &s)

    copy(d.s[BELT_BLOCK_LEN:], s[:])
}

func (d *digest) updateCtr(len_bytes int) {
    /* Perform a simple addition on 128 bits on the first part of the state */
    var a0, a1, b, c uint64

    a0 = getu64(d.s[0:])
    a1 = getu64(d.s[8:])

    b = uint64(len_bytes) << 3

    c = (a0 + b)
    if c < b {
        /* Handle carry */
        a1 += 1
    }

    /* Store the result */
    putu64(d.s[0:], c)
    putu64(d.s[8:], a1)

    return;
}

