package xxhash32

// The size of a xxhash32 hash value in bytes
const Size = 4

// The blocksize of xxhash32 hash function in bytes
const BlockSize = 16

type digest struct {
    s   [4]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    seed uint32
}

func newDigest(seed uint32) *digest {
    d := new(digest)
    d.seed = seed
    d.Reset()
    return d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
    d.s[0] = d.seed + prime[0] + prime[1]
    d.s[1] = d.seed + prime[1]
    d.s[2] = d.seed
    d.s[3] = d.seed - prime[0]

    d.len = 0
    d.nx = 0
}

// Size returns the number of bytes returned by Sum().
func (d *digest) Size() int {
    return Size
}

// BlockSize gives the minimum number of bytes accepted by Write().
func (d *digest) BlockSize() int {
    return BlockSize
}

// Write adds p bytes to the Hash.
func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)

    var xx int

    plen := len(p)
    for d.nx + plen >= BlockSize {
        copy(d.x[d.nx:], p)

        d.compress(d.x[:])

        xx = BlockSize - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

// Sum appends the current hash to in and returns the resulting slice.
func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (d *digest) checkSum() (out [Size]byte) {
    sum := d.Sum32()
    putu32(out[:], sum)

    return
}

// Sum32 returns the 32 bits Hash value.
func (d *digest) Sum32() uint32 {
    tmp := uint32(d.len)

    if d.len >= 16 {
        tmp += rotl(d.s[0], 1) + rotl(d.s[1], 7) + rotl(d.s[2], 12) + rotl(d.s[3], 18)
    } else {
        tmp += d.seed + prime[4]
    }

    p := 0
    n := d.nx
    for n := n - 4; p <= n; p += 4 {
        tmp += getu32(d.x[p:p+4]) * prime[2]
        tmp = rotl(tmp, 17) * prime[3]
    }

    for ; p < n; p++ {
        tmp += uint32(d.x[p]) * prime[4]
        tmp = rotl(tmp, 11) * prime[0]
    }

    tmp ^= tmp >> 15
    tmp *= prime[1]
    tmp ^= tmp >> 13
    tmp *= prime[2]
    tmp ^= tmp >> 16

    return tmp
}

func (d *digest) compress(data []byte) {
    datas := bytesToUint32s(data)

    d.s[0] = rotl(d.s[0] + datas[0] * prime[1], 13) * prime[0]
    d.s[1] = rotl(d.s[1] + datas[1] * prime[1], 13) * prime[0]
    d.s[2] = rotl(d.s[2] + datas[2] * prime[1], 13) * prime[0]
    d.s[3] = rotl(d.s[3] + datas[3] * prime[1], 13) * prime[0]
}

// checksum returns the 32bits Hash value.
func checksum(data []byte, seed uint32) uint32 {
    h := newDigest(seed)
    h.Write(data)

    return h.Sum32()
}
