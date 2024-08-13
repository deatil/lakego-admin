package md6

// The size of a md6 checksum in bytes.
const Size256 = 32
const Size512 = 64

// The blocksize of md6 in bytes.
const BlockSize = 512

const KeySize   = 64

type digest struct {
    s   [128]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    d int
    M []byte
    K [][]uint32
    k int

    r   int
    L   int
    ell int

    C [][]uint32
}

// newDigest returns a new hash.Hash computing the MD6 checksum.
func newDigest(size int, key []byte, levels int) *digest {
    if len(key) > KeySize {
        key = key[:KeySize]
    }

    d := new(digest)

    d.d = size
    d.k = len(key)

    for len(key) < KeySize {
        key = append(key, 0x00)
    }

    d.K = toWord(key)

    if d.k > 0 {
        d.r = tmax(80, (40 + (d.d / 4)))
    } else {
        d.r = tmax(0, (40 + (d.d / 4)))
    }

    d.L = levels
    d.ell = 0
    d.C = [][]uint32{}

    d.Reset()
    return d
}

func (this *digest) Size() int {
    return this.d / 8
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.nx = 0
    this.len = 0

    this.s = [128]uint32{}
    this.x = [BlockSize]byte{}

    this.M = []byte{}
    this.ell = 0

    this.C = [][]uint32{}
}

func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for this.nx + plen >= limit {
        xx := limit - this.nx

        copy(this.x[this.nx:], p)

        plen -= xx
        this.len += uint64(xx)

        this.process(this.x[:], this.len, false)

        p = p[xx:]
        this.nx = 0
    }

    copy(this.x[this.nx:], p)
    this.nx += plen
    this.len += uint64(plen)

    return
}

func (this *digest) Sum(p []byte) []byte {
    d0 := this.copy()
    hash := d0.checkSum()
    return append(p, hash[:]...)
}

func (this *digest) checkSum() (hash []byte) {
    this.process(this.x[:this.nx], this.len, true)

    return crop(this.d, fromWord(this.C), true)
}

func (this *digest) process(M []byte, length uint64, final bool) {
    this.ell += 1

    if this.ell > this.L {
        this.seq(M, final)
    } else {
        this.par(M, length, final)
    }
}

// first
func (this *digest) par(M []byte, length uint64, final bool) {
    var i, p, z int

    z = 1
    if final && length > b {
        z = 0
    }

    var P = 0
    var B [][][]uint32

    for len(M) < 1 || (len(M) % b) > 0 {
        M = append(M, 0x00)
        P += 8
    }

    B = append(B, toWord(M))

    for i, p = 0, 0; i < len(B); i, p = i + 1, 0 {
        if final && i == (len(B) - 1) {
            p = P
        } else {
            p = 0
        }

        this.C = this.mid(B[i], this.C, uint32(i), uint32(p), uint32(z))
    }
}

// per block
func (this *digest) seq(M []byte, final bool) {
    var i, p, z int

    var P = 0
    var B [][][]uint32

    for len(M) < 1 || (len(M) % (b - c)) > 0 {
        M = append(M, 0x00)
        P += 8
    }

    B = append(B, toWord(M))

    for i, p = 0, 0; i < len(B); i, p = i + 1, 0 {
        if final && i == (len(B) - 1) {
            p = P
            z = 1
        } else {
            p = 0
            z = 0
        }

        this.C = this.mid(B[i], this.C, uint32(i), uint32(p), uint32(z))
    }
}

func (this *digest) f(N [][]uint32) [][]uint32 {
    var i, j, s int

    S := make([]uint32, len(S0))
    x := make([]uint32, len(S))
    A := make([][]uint32, n + this.r * 16)

    for i := range A {
        A[i] = make([]uint32, 2)
    }

    copy(S, S0)
    copy(A, N)

    for j, i = 0, n; j < this.r; j, i = j + 1, i + 16 {
        for s = 0; s < 16; s++ {
            copy(x, S)

            x = xor(x, A[i + s - t[5]])
            x = xor(x, A[i + s - t[0]])
            x = xor(x, and(A[i + s - t[1]], A[i + s - t[2]]))
            x = xor(x, and(A[i + s - t[3]], A[i + s - t[4]]))
            x = xor(x, shr(x, rs[s]))

            A[i + s] = xor(x, shl(x, ls[s]))
        }

        S = xor(xor(shl(S, 1), shr(S, (64 - 1))), and(S, Sm))
    }

    return A[len(A) - 16:]
}

func (this *digest) mid(B, C [][]uint32, i, p, z uint32) [][]uint32 {
    U := []uint32{
        (uint32(this.ell) & 0xFF) << 24 | (i / 0xFFFFFFFF) & 0xFFFFFF,
        i & 0xFFFFFFFF,
    }

    V := []uint32{
        ((uint32(this.r) & 0xFFF) << 16) | ((uint32(this.L) & 0xFF) << 8) | ((z & 0xF) << 4) | ((p & 0xF000) >> 12),
        (((p & 0xFFF) << 20) | ((uint32(this.k) & 0xFF) << 12) | ((uint32(this.d) & 0xFFF))),
    }

    var in [][]uint32
    in = append(in, Q...)
    in = append(in, this.K...)
    in = append(in, U)
    in = append(in, V)
    in = append(in, C...)
    in = append(in, B...)

    return this.f(in)
}

func (this *digest) copy() *digest {
    nd := &digest{
        s:   this.s,
        x:   this.x,
        nx:  this.nx,
        len: this.len,

        d: this.d,
        M: make([]byte, len(this.M)),
        K: make([][]uint32, len(this.K)),
        k: this.k,

        r:   this.r,
        L:   this.L,
        ell: this.ell,

        C: make([][]uint32, len(this.C)),
    }
    copy(nd.M, this.M)
    copy(nd.K, this.K)
    copy(nd.C, this.C)

    return nd
}
