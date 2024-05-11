package panama

// The size of an panama checksum in bytes.
const Size = 32

// The blocksize of panama in bytes.
const BlockSize = 32

type digest struct {
    s   [17]uint32
    x   [32]byte
    nx  int
    len uint64

    buffer    [256]uint32
    bufferPtr uint32
}

// newDigest returns a new *digest.
func newDigest() *digest {
    d := new(digest)
    d.Reset()
    return d
}

func (this *digest) Reset() {
    this.s = [17]uint32{}
    this.x = [32]byte{}
    this.nx = 0
    this.len = 0

    this.buffer = [256]uint32{}
    this.bufferPtr = 0
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

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
    d0 := *this
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (this *digest) checkSum() (out [Size]byte) {
    var pad = make([]byte, BlockSize)
    copy(pad[:], this.x[:this.nx])

    pad[this.nx] = 0x01
    this.processBlock(pad)

    for i := 0; i < 32; i++ {
        this.oneStep(nil, false)
    }

    sum := uint32sToBytes(this.s[9:])
    copy(out[:], sum)

    return
}

func (this *digest) processBlock(data []byte) {
    this.oneStep(data, true)
}

func (this *digest) oneStep(data []byte, push bool) {
    var inData []uint32

    if push {
        inData = bytesToUint32s(data)
    }

    /*
     * Buffer update.
     */
    ptr0 := this.bufferPtr
    ptr24 := (ptr0 - 64) & 248
    ptr31 := (ptr0 - 8) & 248

    if push {
        this.buffer[ptr24 + 0] ^= this.buffer[ptr31 + 2]
        this.buffer[ptr31 + 2] ^= inData[2]
        this.buffer[ptr24 + 1] ^= this.buffer[ptr31 + 3]
        this.buffer[ptr31 + 3] ^= inData[3]
        this.buffer[ptr24 + 2] ^= this.buffer[ptr31 + 4]
        this.buffer[ptr31 + 4] ^= inData[4]
        this.buffer[ptr24 + 3] ^= this.buffer[ptr31 + 5]
        this.buffer[ptr31 + 5] ^= inData[5]
        this.buffer[ptr24 + 4] ^= this.buffer[ptr31 + 6]
        this.buffer[ptr31 + 6] ^= inData[6]
        this.buffer[ptr24 + 5] ^= this.buffer[ptr31 + 7]
        this.buffer[ptr31 + 7] ^= inData[7]
        this.buffer[ptr24 + 6] ^= this.buffer[ptr31 + 0]
        this.buffer[ptr31 + 0] ^= inData[0]
        this.buffer[ptr24 + 7] ^= this.buffer[ptr31 + 1]
        this.buffer[ptr31 + 1] ^= inData[1]
    } else {
        this.buffer[ptr24 + 0] ^= this.buffer[ptr31 + 2]
        this.buffer[ptr31 + 2] ^= this.s[3]
        this.buffer[ptr24 + 1] ^= this.buffer[ptr31 + 3]
        this.buffer[ptr31 + 3] ^= this.s[4]
        this.buffer[ptr24 + 2] ^= this.buffer[ptr31 + 4]
        this.buffer[ptr31 + 4] ^= this.s[5]
        this.buffer[ptr24 + 3] ^= this.buffer[ptr31 + 5]
        this.buffer[ptr31 + 5] ^= this.s[6]
        this.buffer[ptr24 + 4] ^= this.buffer[ptr31 + 6]
        this.buffer[ptr31 + 6] ^= this.s[7]
        this.buffer[ptr24 + 5] ^= this.buffer[ptr31 + 7]
        this.buffer[ptr31 + 7] ^= this.s[8]
        this.buffer[ptr24 + 6] ^= this.buffer[ptr31 + 0]
        this.buffer[ptr31 + 0] ^= this.s[1]
        this.buffer[ptr24 + 7] ^= this.buffer[ptr31 + 1]
        this.buffer[ptr31 + 1] ^= this.s[2]
    }
    this.bufferPtr = ptr31

    /*
     * Gamma transform.
     */
    var g0, g1, g2, g3, g4, g5, g6, g7, g8, g9 uint32
    var g10, g11, g12, g13, g14, g15, g16 uint32
    g0  = this.s[0]  ^ (this.s[1]  | ^this.s[2] )
    g1  = this.s[1]  ^ (this.s[2]  | ^this.s[3] )
    g2  = this.s[2]  ^ (this.s[3]  | ^this.s[4] )
    g3  = this.s[3]  ^ (this.s[4]  | ^this.s[5] )
    g4  = this.s[4]  ^ (this.s[5]  | ^this.s[6] )
    g5  = this.s[5]  ^ (this.s[6]  | ^this.s[7] )
    g6  = this.s[6]  ^ (this.s[7]  | ^this.s[8] )
    g7  = this.s[7]  ^ (this.s[8]  | ^this.s[9] )
    g8  = this.s[8]  ^ (this.s[9]  | ^this.s[10])
    g9  = this.s[9]  ^ (this.s[10] | ^this.s[11])
    g10 = this.s[10] ^ (this.s[11] | ^this.s[12])
    g11 = this.s[11] ^ (this.s[12] | ^this.s[13])
    g12 = this.s[12] ^ (this.s[13] | ^this.s[14])
    g13 = this.s[13] ^ (this.s[14] | ^this.s[15])
    g14 = this.s[14] ^ (this.s[15] | ^this.s[16])
    g15 = this.s[15] ^ (this.s[16] | ^this.s[0] )
    g16 = this.s[16] ^ (this.s[0]  | ^this.s[1] )

    /*
     * Pi transform.
     */
    var p0, p1, p2, p3, p4, p5, p6, p7, p8, p9 uint32
    var p10, p11, p12, p13, p14, p15, p16 uint32
    p0  = g0
    p1  = ( g7 <<  1) | ( g7 >> (32 -  1))
    p2  = (g14 <<  3) | (g14 >> (32 -  3))
    p3  = ( g4 <<  6) | ( g4 >> (32 -  6))
    p4  = (g11 << 10) | (g11 >> (32 - 10))
    p5  = ( g1 << 15) | ( g1 >> (32 - 15))
    p6  = ( g8 << 21) | ( g8 >> (32 - 21))
    p7  = (g15 << 28) | (g15 >> (32 - 28))
    p8  = ( g5 <<  4) | ( g5 >> (32 -  4))
    p9  = (g12 << 13) | (g12 >> (32 - 13))
    p10 = ( g2 << 23) | ( g2 >> (32 - 23))
    p11 = ( g9 <<  2) | ( g9 >> (32 -  2))
    p12 = (g16 << 14) | (g16 >> (32 - 14))
    p13 = ( g6 << 27) | ( g6 >> (32 - 27))
    p14 = (g13 <<  9) | (g13 >> (32 -  9))
    p15 = ( g3 << 24) | ( g3 >> (32 - 24))
    p16 = (g10 <<  8) | (g10 >> (32 -  8))

    /*
     * Theta transform.
     */
    var t0, t1, t2, t3, t4, t5, t6, t7, t8, t9 uint32
    var t10, t11, t12, t13, t14, t15, t16 uint32
    t0  = p0  ^ p1  ^ p4
    t1  = p1  ^ p2  ^ p5
    t2  = p2  ^ p3  ^ p6
    t3  = p3  ^ p4  ^ p7
    t4  = p4  ^ p5  ^ p8
    t5  = p5  ^ p6  ^ p9
    t6  = p6  ^ p7  ^ p10
    t7  = p7  ^ p8  ^ p11
    t8  = p8  ^ p9  ^ p12
    t9  = p9  ^ p10 ^ p13
    t10 = p10 ^ p11 ^ p14
    t11 = p11 ^ p12 ^ p15
    t12 = p12 ^ p13 ^ p16
    t13 = p13 ^ p14 ^ p0
    t14 = p14 ^ p15 ^ p1
    t15 = p15 ^ p16 ^ p2
    t16 = p16 ^ p0  ^ p3

    /*
     * Sigma transform.
     */
    ptr16 := ptr0 ^ 128
    this.s[0] = t0 ^ 1
    if (push) {
        this.s[1] = t1 ^ inData[0]
        this.s[2] = t2 ^ inData[1]
        this.s[3] = t3 ^ inData[2]
        this.s[4] = t4 ^ inData[3]
        this.s[5] = t5 ^ inData[4]
        this.s[6] = t6 ^ inData[5]
        this.s[7] = t7 ^ inData[6]
        this.s[8] = t8 ^ inData[7]
    } else {
        ptr4 := (ptr0 + 32) & 248
        this.s[1] = t1 ^ this.buffer[ptr4 + 0]
        this.s[2] = t2 ^ this.buffer[ptr4 + 1]
        this.s[3] = t3 ^ this.buffer[ptr4 + 2]
        this.s[4] = t4 ^ this.buffer[ptr4 + 3]
        this.s[5] = t5 ^ this.buffer[ptr4 + 4]
        this.s[6] = t6 ^ this.buffer[ptr4 + 5]
        this.s[7] = t7 ^ this.buffer[ptr4 + 6]
        this.s[8] = t8 ^ this.buffer[ptr4 + 7]
    }
    this.s[9]  = t9  ^ this.buffer[ptr16 + 0]
    this.s[10] = t10 ^ this.buffer[ptr16 + 1]
    this.s[11] = t11 ^ this.buffer[ptr16 + 2]
    this.s[12] = t12 ^ this.buffer[ptr16 + 3]
    this.s[13] = t13 ^ this.buffer[ptr16 + 4]
    this.s[14] = t14 ^ this.buffer[ptr16 + 5]
    this.s[15] = t15 ^ this.buffer[ptr16 + 6]
    this.s[16] = t16 ^ this.buffer[ptr16 + 7]
}
