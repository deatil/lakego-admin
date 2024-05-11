package whirlpool

// The size of a whirlpool checksum in bytes.
const Size = 64

// The blocksize of whirlpool in bytes.
const BlockSize = 64

const rounds      = 10
const lengthBytes = 32

type digest struct {
    s    [lengthBytes]byte
    x    [BlockSize]byte
    nx   int
    len  int

    hash [8]uint64

    c  [8][256]uint64
    rc [rounds + 1]uint64
}

// newDigest returns a new hash.Hash computing the Whirlpool checksum.
func newDigest(c [8][256]uint64, rc [rounds + 1]uint64) *digest {
    h := new(digest)
    h.c = c
    h.rc = rc
    h.Reset()

    return h
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.s = [lengthBytes]byte{}
    this.x = [BlockSize]byte{}
    this.nx = 0
    this.len = 0

    this.hash = [8]uint64{}
}

func (this *digest) Write(p []byte) (int, error) {
    var (
        sourcePos  int
        nn         int    = len(p)
        sourceBits uint64 = uint64(nn * 8)
        sourceGap  uint   = uint((8 - (int(sourceBits & 7))) & 7)
        bufferRem  uint   = uint(this.len & 7)
        b          uint32
    )

    // Tally the length of the data added.
    for i, carry, value := 31, uint32(0), uint64(sourceBits); i >= 0 && (carry != 0 || value != 0); i-- {
        carry += uint32(this.s[i]) + (uint32(value & 0xff))
        this.s[i] = byte(carry)
        carry >>= 8
        value >>= 8
    }

    // Process data in chunks of 8 bits.
    for sourceBits > 8 {
        b = uint32(((p[sourcePos] << sourceGap) & 0xff) |
            ((p[sourcePos+1] & 0xff) >> (8 - sourceGap)))

        this.x[this.nx] |= uint8(b >> bufferRem)
        this.nx++
        this.len += int(8 - bufferRem)

        if this.len == (8 * Size) {
            this.transform()

            this.len = 0
            this.nx = 0
        }

        this.x[this.nx] = byte(b << (8 - bufferRem))
        this.len += int(bufferRem)

        sourceBits -= 8
        sourcePos++
    }

    if sourceBits > 0 {
        b = uint32((p[sourcePos] << sourceGap) & 0xff)

        this.x[this.nx] |= byte(b) >> bufferRem
    } else {
        b = 0
    }

    if uint64(bufferRem) + sourceBits < 8 {
        this.len += int(sourceBits)
    } else {
        this.nx++

        this.len += 8 - int(bufferRem)
        sourceBits -= uint64(8 - bufferRem)

        if this.len == (8 * Size) {
            this.transform()

            this.len = 0
            this.nx = 0
        }

        this.x[this.nx] = byte(b << (8 - bufferRem))
        this.len += int(sourceBits)
    }

    return nn, nil
}

func (this *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *this
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (this *digest) checkSum() []byte {
    this.x[this.nx] |= 0x80 >> (uint(this.len) & 7)
    this.nx++

    if this.nx > BlockSize-lengthBytes {
        if this.nx < BlockSize {
            for i := 0; i < BlockSize-this.nx; i++ {
                this.x[this.nx+i] = 0
            }
        }

        this.transform()

        this.nx = 0
    }

    if this.nx < BlockSize-lengthBytes {
        for i := 0; i < (BlockSize - lengthBytes) - this.nx; i++ {
            this.x[this.nx + i] = 0
        }
    }
    this.nx = BlockSize - lengthBytes

    for i := 0; i < lengthBytes; i++ {
        this.x[this.nx + i] = this.s[i]
    }

    this.transform()

    digest := uint64sToBytes(this.hash[:])
    return digest[:Size]
}

func (this *digest) transform() {
    var K, state, L [8]uint64

    block := bytesToUint64s(this.x[:])

    for i := 0; i < 8; i++ {
        K[i] = this.hash[i]
        state[i] = block[i] ^ K[i]
    }

    c0 := this.c[0]
    c1 := this.c[1]
    c2 := this.c[2]
    c3 := this.c[3]
    c4 := this.c[4]
    c5 := this.c[5]
    c6 := this.c[6]
    c7 := this.c[7]

    for r := 1; r <= rounds; r++ {
        // Compute K^rounds from K^(rounds-1).
        for i := 0; i < 8; i++ {
            L[i] = c0[byte(K[i%8]>>56)] ^
                c1[byte(K[(i+7)%8]>>48)] ^
                c2[byte(K[(i+6)%8]>>40)] ^
                c3[byte(K[(i+5)%8]>>32)] ^
                c4[byte(K[(i+4)%8]>>24)] ^
                c5[byte(K[(i+3)%8]>>16)] ^
                c6[byte(K[(i+2)%8]>>8)] ^
                c7[byte(K[(i+1)%8])]
        }

        L[0] ^= this.rc[r]

        for i := 0; i < 8; i++ {
            K[i] = L[i]
        }

        // Apply r-th round transformation.
        for i := 0; i < 8; i++ {
            L[i] = c0[byte(state[ i   %8]>>56)] ^
                   c1[byte(state[(i+7)%8]>>48)] ^
                   c2[byte(state[(i+6)%8]>>40)] ^
                   c3[byte(state[(i+5)%8]>>32)] ^
                   c4[byte(state[(i+4)%8]>>24)] ^
                   c5[byte(state[(i+3)%8]>>16)] ^
                   c6[byte(state[(i+2)%8]>> 8)] ^
                   c7[byte(state[(i+1)%8]    )] ^
                   K[i%8]
        }

        for i := 0; i < 8; i++ {
            state[i] = L[i]
        }
    }

    for i := 0; i < 8; i++ {
        this.hash[i] ^= state[i] ^ block[i]
    }
}
