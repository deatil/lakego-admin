package xxhash64

// The size of a xxhash64 hash value in bytes
const Size = 8

// The blocksize of xxhash64 hash function in bytes
const BlockSize = 32

type digest struct {
    s   [4]uint64
    x   [BlockSize]byte
    nx  int
    len uint64

    seed uint64
}

// newDigest returns a new digest instance.
func newDigest(seed uint64) *digest {
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

// Sum appends the current hash to b and returns the resulting slice.
func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (d *digest) checkSum() (out [Size]byte) {
    sum := d.Sum64()
    putu64(out[:], sum)

    return
}

// Sum64 returns the 64bits Hash value.
func (d *digest) Sum64() uint64 {
    var tmp uint64

    if d.len >= 32 {
        tmp = rotl(d.s[0], 1) + rotl(d.s[1], 7) + rotl(d.s[2], 12) + rotl(d.s[3], 18)

        d.s[0] *= prime[1]
        d.s[1] *= prime[1]
        d.s[2] *= prime[1]
        d.s[3] *= prime[1]

        tmp = (tmp ^ (rotl(d.s[0], 31) * prime[0])) * prime[0] + prime[3]
        tmp = (tmp ^ (rotl(d.s[1], 31) * prime[0])) * prime[0] + prime[3]
        tmp = (tmp ^ (rotl(d.s[2], 31) * prime[0])) * prime[0] + prime[3]
        tmp = (tmp ^ (rotl(d.s[3], 31) * prime[0])) * prime[0] + prime[3]

        tmp += d.len
    } else {
        tmp = d.seed + prime[4] + d.len
    }

    p := 0
    n := d.nx
    for n := n - 8; p <= n; p += 8 {
        tmp ^= rotl(getu64(d.x[p:]) * prime[1], 31) * prime[0]
        tmp = rotl(tmp, 27) * prime[0] + prime[3]
    }

    if p + 4 <= n {
        sub := d.x[p : p+4]
        tmp ^= uint64(getu32(sub)) * prime[0]
        tmp = rotl(tmp, 23)*prime[1] + prime[2]
        p += 4
    }

    for ; p < n; p++ {
        tmp ^= uint64(d.x[p]) * prime[4]
        tmp = rotl(tmp, 11) * prime[0]
    }

    tmp ^= tmp >> 33
    tmp *= prime[1]
    tmp ^= tmp >> 29
    tmp *= prime[2]
    tmp ^= tmp >> 32

    return tmp
}

func (d *digest) compress(data []byte) {
    datas := bytesToUint64s(data)

    d.s[0] = rotl(d.s[0] + datas[0] * prime[1], 31) * prime[0]
    d.s[1] = rotl(d.s[1] + datas[1] * prime[1], 31) * prime[0]
    d.s[2] = rotl(d.s[2] + datas[2] * prime[1], 31) * prime[0]
    d.s[3] = rotl(d.s[3] + datas[3] * prime[1], 31) * prime[0]
}

// checksum returns the 64bits Hash value.
func checksum(data []byte, seed uint64) uint64 {
    h := newDigest(seed)
    h.Write(data)

    return h.Sum64()
}
