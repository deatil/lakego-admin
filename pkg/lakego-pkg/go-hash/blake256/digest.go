package blake256

const (
    // The size of BLAKE-256 hash in bytes.
    Size = 32

    // The size of BLAKE-224 hash in bytes.
    Size224 = 28

    // The block size of the hash algorithm in bytes.
    BlockSize = 64
)

type digest struct {
    s     [4]uint32
    x     [BlockSize]byte
    nx    int
    len   uint64

    h     [8]uint32
    t     uint64
    nullt bool

    hs      int
    initVal [8]uint32
}

func newDigest(hs int, iv [8]uint32) *digest {
    d := new(digest)
    d.hs = hs
    d.initVal = iv
    d.Reset()

    return d
}

// Reset resets the state of digest. It leaves salt intact.
func (d *digest) Reset() {
    d.s = [4]uint32{}
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0

    d.h = d.initVal
    d.t = 0
    d.nullt = false
}

func (d *digest) Size() int {
    return d.hs / 8
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)

    var limit = BlockSize
    for d.nx + plen >= limit {
        xx := limit - d.nx

        copy(d.x[d.nx:], p)
        d.compress(d.x[:])

        plen -= xx
        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

// Sum returns the checksum.
func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d0 so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()

    return append(in, sum[:]...)
}

func (d *digest) checkSum() (out []byte) {
    nx := uint64(d.nx)

    l := d.t + nx<<3

    var msglen [8]byte
    putu64(msglen[:], l)

    if nx == 55 {
        // One padding byte.
        d.t -= 8
        if d.hs == 224 {
            d.Write([]byte{0x80})
        } else {
            d.Write([]byte{0x81})
        }
    } else {
        if nx < 55 {
            // Enough space to fill the block.
            if nx == 0 {
                d.nullt = true
            }

            d.t -= 440 - nx<<3
            d.Write(pad[0 : 55-nx])
        } else {
            // Need 2 compressions.
            d.t -= 512 - nx<<3
            d.Write(pad[0 : 64-nx])

            d.t -= 440
            d.Write(pad[1 : 56])

            d.nullt = true
        }

        if d.hs == 224 {
            d.Write([]byte{0x00})
        } else {
            d.Write([]byte{0x01})
        }

        d.t -= 8
    }

    d.t -= 64
    d.Write(msglen[:])

    out = make([]byte, d.Size())

    sum := uint32sToBytes(d.h[:d.hs>>5])
    copy(out[:], sum)

    return
}

func (d *digest) compress(p []uint8) {
    var v [16]uint32
    var i int

    m := bytesToUint32s(p)

    for i = 0; i < 8; i++ {
        v[i] = d.h[i]
    }

    v[ 8] = d.s[0] ^ u256[0]
    v[ 9] = d.s[1] ^ u256[1]
    v[10] = d.s[2] ^ u256[2]
    v[11] = d.s[3] ^ u256[3]
    v[12] = u256[4]
    v[13] = u256[5]
    v[14] = u256[6]
    v[15] = u256[7]

    d.t += 512

    /* don't xor t when the block is only padding */
    if !d.nullt {
        v[12] ^= uint32(d.t)
        v[13] ^= uint32(d.t)
        v[14] ^= uint32(d.t >> 32)
        v[15] ^= uint32(d.t >> 32)
    }

    for i = 0; i < 14; i++ {
        /* column step */
        G(&v, m, i, 0,  4,  8, 12,  0)
        G(&v, m, i, 1,  5,  9, 13,  2)
        G(&v, m, i, 2,  6, 10, 14,  4)
        G(&v, m, i, 3,  7, 11, 15,  6)

        /* diagonal step */
        G(&v, m, i, 0,  5, 10, 15,  8)
        G(&v, m, i, 1,  6, 11, 12, 10)
        G(&v, m, i, 2,  7,  8, 13, 12)
        G(&v, m, i, 3,  4,  9, 14, 14)
    }

    for i = 0; i < 16; i++ {
        d.h[i % 8] ^= v[i]
    }

    for i = 0; i < 8 ; i++ {
        d.h[i] ^= d.s[i % 4]
    }
}

func (d *digest) setSalt(s []byte) {
    if len(s) != 16 {
        panic("salt length must be 16 bytes")
    }

    ss := bytesToUint32s(s)
    copy(d.s[:], ss)
}
