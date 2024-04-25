// PMAC message authentication code, defined in
// http://web.cs.ucdavis.edu/~rogaway/ocb/pmac.pdf
package pmac

import (
    "hash"
    "errors"
    "math/bits"
    "crypto/cipher"
    "crypto/subtle"
)

var (
    errUnsupportedCipher = errors.New("cipher block size not supported")
    errInvalidTagSize    = errors.New("tags size must between 1 and the cipher's block size")
)

type pmac struct {
    // c is the block cipher we're using (i.e. AES-128 or AES-256)
    c cipher.Block

    l []Block

    lInv Block

    // digest contains the PMAC tag-in-progress
    digest Block

    // offset is a block specific tweak to the input message
    offset Block

    // buf contains a part of the input message, processed a block-at-a-time
    buf Block

    // pos marks the end of plaintext in the buf
    pos uint

    // ctr is the number of blocks we have MAC'd so far
    ctr uint

    // finished is set true when we are done processing a message, and forbids
    // any subsequent writes until we reset the internal state
    finished bool

    // precomputedBlocks
    // Number of L blocks to precompute
    // (i.e. µ in the PMAC paper)
    pcbs int

    // tagsize
    tagsize int
}

// New creates a new PMAC instance using the given cipher
func New(c cipher.Block) (hash.Hash, error) {
    return NewWithTagSize(c, c.BlockSize())
}

// NewWithTagSize returns a hash.Hash computing the PMAC checksum with the
// given tag size. The tag size must between the 1 and the cipher's block size.
func NewWithTagSize(c cipher.Block, tagsize int) (hash.Hash, error) {
    blocksize := c.BlockSize()

    if tagsize <= 0 || tagsize > blocksize {
        return nil, errInvalidTagSize
    }

    switch blocksize {
        case 8, 16, 32, 64, 128:
            //
        default:
            return nil, errUnsupportedCipher
    }

    d := new(pmac)
    d.c = c
    d.pcbs = 2*blocksize-1
    d.tagsize = tagsize

    tmp := NewBlock(d.tagsize)
    tmp.Encrypt(c)

    d.l = make([]Block, d.pcbs)

    d.lInv = NewBlock(d.tagsize)
    d.digest = NewBlock(d.tagsize)
    d.offset = NewBlock(d.tagsize)
    d.buf = NewBlock(d.tagsize)

    for i := range d.l {
        d.l[i] = NewBlock(d.tagsize)

        copy(d.l[i].Data, tmp.Data)
        tmp.Dbl()
    }

    // Compute L(−1) ← L · x⁻¹:
    //
    //     a>>1 if lastbit(a)=0
    //     (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
    //
    copy(tmp.Data, d.l[0].Data)
    lastBit := int(tmp.Data[d.tagsize-1] & 0x01)

    for i := d.tagsize - 1; i > 0; i-- {
        carry := byte(subtle.ConstantTimeSelect(int(tmp.Data[i-1]&1), 0x80, 0))
        tmp.Data[i] = (tmp.Data[i] >> 1) | carry
    }

    tmp.Data[0] >>= 1
    tmp.Data[0] ^= byte(subtle.ConstantTimeSelect(lastBit, 0x80, 0))
    tmp.Data[d.tagsize-1] ^= byte(subtle.ConstantTimeSelect(lastBit, R>>1, 0))
    copy(d.lInv.Data, tmp.Data)

    return d, nil
}

// Reset clears the digest state, starting a new digest.
func (d *pmac) Reset() {
    d.digest.Clear()
    d.offset.Clear()
    d.buf.Clear()
    d.pos = 0
    d.ctr = 0
    d.finished = false
}

func (d *pmac) Size() int {
    return d.tagsize
}

func (d *pmac) BlockSize() int {
    return d.tagsize
}

// Write adds the given data to the digest state.
func (d *pmac) Write(msg []byte) (int, error) {
    if d.finished {
        panic("pmac: already finished")
    }

    var msgPos, msgLen, remaining uint
    msgLen = uint(len(msg))
    remaining = uint(d.tagsize) - d.pos

    // Finish filling the internal buf with the message
    if msgLen > remaining {
        copy(d.buf.Data[d.pos:], msg[:remaining])

        msgPos += remaining
        msgLen -= remaining

        d.processBuffer()
    }

    // So long as we have more than a blocks worth of data, compute
    // whole-sized blocks at a time.
    for msgLen > uint(d.tagsize) {
        copy(d.buf.Data[:], msg[msgPos:msgPos+uint(d.tagsize)])

        msgPos += uint(d.tagsize)
        msgLen -= uint(d.tagsize)

        d.processBuffer()
    }

    if msgLen > 0 {
        copy(d.buf.Data[d.pos:d.pos+msgLen], msg[msgPos:])
        d.pos += msgLen
    }

    return len(msg), nil
}

// Sum returns the PMAC digest, one cipher block in length,
// of the data written with Write.
func (d *pmac) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

// Sum returns the CMAC digest, one cipher block in length,
// of the data written with Write.
func (d *pmac) checkSum() []byte {
    if d.finished {
        panic("pmac: already finished")
    }

    if d.pos == uint(d.tagsize) {
        xor(d.digest.Data, d.buf.Data)
        xor(d.digest.Data, d.lInv.Data)
    } else {
        xor(d.digest.Data, d.buf.Data[:d.pos])
        d.digest.Data[d.pos] ^= 0x80
    }

    d.digest.Encrypt(d.c)
    d.finished = true

    return d.digest.Data
}

// Update the internal tag state based on the buf contents
func (d *pmac) processBuffer() {
    xor(d.offset.Data, d.l[bits.TrailingZeros(d.ctr+1)].Data)
    xor(d.buf.Data, d.offset.Data)
    d.ctr++

    d.buf.Encrypt(d.c)
    xor(d.digest.Data, d.buf.Data)
    d.pos = 0
}

// XOR the contents of b into a in-place
func xor(a, b []byte) {
    subtle.XORBytes(a, a, b)
}
