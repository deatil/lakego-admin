package tiger

// The size list of a Tiger hash value in bytes
const Size128 = 16
const Size160 = 20
const Size192 = 24

// The blocksize of Tiger hash function in bytes
const BlockSize = 64

type digest struct {
    s   [3]uint64
    x   [BlockSize]byte
    nx  int
    len uint64

    hs  int
    ver int
}

// newDigest returns a new digest computing the Tiger hash value
func newDigest(hs int, ver int) *digest {
    d := new(digest)
    d.hs = hs
    d.ver = ver
    d.Reset()

    return d
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Reset() {
    d.s = initH
    d.nx = 0
    d.len = 0
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)

    var xx int
    for d.nx + plen >= BlockSize {
        xx = BlockSize - d.nx

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

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest) checkSum() []byte {
    var tmp [64]byte

    if d.ver == 1 {
        tmp[0] = 0x01
    } else {
        tmp[0] = 0x80
    }

    length := d.len

    size := length & 0x3f
    if size < 56 {
        d.Write(tmp[:56-size])
    } else {
        d.Write(tmp[:64+56-size])
    }

    length <<= 3
    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(length >> (8 * i))
    }

    d.Write(tmp[:8])

    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(d.s[0] >> (8 * i))
        tmp[i+8] = byte(d.s[1] >> (8 * i))
        tmp[i+16] = byte(d.s[2] >> (8 * i))
    }

    return tmp[:d.hs]
}

func (d *digest) compress(data []byte) {
    a := d.s[0]
    b := d.s[1]
    c := d.s[2]

    x := bytesToUint64s(data)

    d.s[0], d.s[1], d.s[2] = pass(d.s[0], d.s[1], d.s[2], x, 5)

    keySchedule(x)
    d.s[2], d.s[0], d.s[1] = pass(d.s[2], d.s[0], d.s[1], x, 7)

    keySchedule(x)
    d.s[1], d.s[2], d.s[0] = pass(d.s[1], d.s[2], d.s[0], x, 9)

    d.s[0] ^= a
    d.s[1] -= b
    d.s[2] += c
}
