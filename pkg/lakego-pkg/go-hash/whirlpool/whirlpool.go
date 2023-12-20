package whirlpool

import (
    "hash"
    "encoding/binary"
)

// The size of a whirlpool checksum in bytes.
const Size = 64

// The blocksize of whirlpool in bytes.
const BlockSize = 64

const rounds      = 10
const lengthBytes = 32

type digest struct {
    bitLength  [lengthBytes]byte
    buffer     [BlockSize]byte
    bufferBits int
    bufferPos  int
    hash       [8]uint64
}

// New returns a new hash.Hash computing the whirlpool checksum.
func New() hash.Hash {
    h := new(digest)
    h.Reset()

    return h
}

// Sum returns the whirlpool checksum of the data.
func Sum(data []byte) (sum [Size]byte) {
    var h digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.buffer = [BlockSize]byte{}
    this.bufferBits = 0
    this.bufferPos = 0

    this.hash = [8]uint64{}

    this.bitLength = [lengthBytes]byte{}
}

func (this *digest) Write(p []byte) (int, error) {
    var (
        sourcePos  int
        nn         int    = len(p)
        sourceBits uint64 = uint64(nn * 8)
        sourceGap  uint   = uint((8 - (int(sourceBits & 7))) & 7)
        bufferRem  uint   = uint(this.bufferBits & 7)
        b          uint32
    )

    // Tally the length of the data added.
    for i, carry, value := 31, uint32(0), uint64(sourceBits); i >= 0 && (carry != 0 || value != 0); i-- {
        carry += uint32(this.bitLength[i]) + (uint32(value & 0xff))
        this.bitLength[i] = byte(carry)
        carry >>= 8
        value >>= 8
    }

    // Process data in chunks of 8 bits.
    for sourceBits > 8 {
        // Take a byte form the p.
        b = uint32(((p[sourcePos] << sourceGap) & 0xff) |
            ((p[sourcePos+1] & 0xff) >> (8 - sourceGap)))

        // Process this byte.
        this.buffer[this.bufferPos] |= uint8(b >> bufferRem)
        this.bufferPos++
        this.bufferBits += int(8 - bufferRem)

        if this.bufferBits == (8 * Size) {
            // Process this block.
            this.transform()

            this.bufferBits = 0
            this.bufferPos = 0
        }

        this.buffer[this.bufferPos] = byte(b << (8 - bufferRem))
        this.bufferBits += int(bufferRem)

        // Proceed to remaining data.
        sourceBits -= 8
        sourcePos++
    }

    // 0 <= sourceBits <= 8; All data leftover is in p[sourcePos].
    if sourceBits > 0 {
        b = uint32((p[sourcePos] << sourceGap) & 0xff)

        this.buffer[this.bufferPos] |= byte(b) >> bufferRem
    } else {
        b = 0
    }

    if uint64(bufferRem) + sourceBits < 8 {
        this.bufferBits += int(sourceBits)
    } else {
        this.bufferPos++

        // bufferBits = 8*bufferPos
        this.bufferBits += 8 - int(bufferRem)
        sourceBits -= uint64(8 - bufferRem)

        if this.bufferBits == (8 * Size) {

            this.transform()

            this.bufferBits = 0
            this.bufferPos = 0
        }

        this.buffer[this.bufferPos] = byte(b << (8 - bufferRem))
        this.bufferBits += int(sourceBits)
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
    this.buffer[this.bufferPos] |= 0x80 >> (uint(this.bufferBits) & 7)
    this.bufferPos++

    if this.bufferPos > BlockSize-lengthBytes {
        if this.bufferPos < BlockSize {
            for i := 0; i < BlockSize-this.bufferPos; i++ {
                this.buffer[this.bufferPos+i] = 0
            }
        }

        this.transform()

        this.bufferPos = 0
    }

    if this.bufferPos < BlockSize-lengthBytes {
        for i := 0; i < (BlockSize - lengthBytes) - this.bufferPos; i++ {
            this.buffer[this.bufferPos + i] = 0
        }
    }
    this.bufferPos = BlockSize - lengthBytes

    // Append the bit length of the hashed data.
    for i := 0; i < lengthBytes; i++ {
        this.buffer[this.bufferPos + i] = this.bitLength[i]
    }

    // Process this data block.
    this.transform()

    // Return the final digest as []byte.
    var digest [Size]byte
    for i := 0; i < Size/8; i++ {
        digest[i*8 + 0] = byte(this.hash[i] >> 56)
        digest[i*8 + 1] = byte(this.hash[i] >> 48)
        digest[i*8 + 2] = byte(this.hash[i] >> 40)
        digest[i*8 + 3] = byte(this.hash[i] >> 32)
        digest[i*8 + 4] = byte(this.hash[i] >> 24)
        digest[i*8 + 5] = byte(this.hash[i] >> 16)
        digest[i*8 + 6] = byte(this.hash[i] >> 8)
        digest[i*8 + 7] = byte(this.hash[i])
    }

    return digest[:Size]
}

func (this *digest) transform() {
    var (
        K     [8]uint64
        block [8]uint64
        state [8]uint64
        L     [8]uint64
    )

    for i := 0; i < 8; i++ {
        b := 8 * i
        block[i] = binary.BigEndian.Uint64(this.buffer[b:])
    }

    for i := 0; i < 8; i++ {
        K[i] = this.hash[i]
        state[i] = block[i] ^ K[i]
    }

    // Iterate over all the rounds.
    for r := 1; r <= rounds; r++ {
        // Compute K^rounds from K^(rounds-1).
        for i := 0; i < 8; i++ {
            L[i] = C0[byte(K[i%8]>>56)] ^
                C1[byte(K[(i+7)%8]>>48)] ^
                C2[byte(K[(i+6)%8]>>40)] ^
                C3[byte(K[(i+5)%8]>>32)] ^
                C4[byte(K[(i+4)%8]>>24)] ^
                C5[byte(K[(i+3)%8]>>16)] ^
                C6[byte(K[(i+2)%8]>>8)] ^
                C7[byte(K[(i+1)%8])]
        }
        L[0] ^= rc[r]

        for i := 0; i < 8; i++ {
            K[i] = L[i]
        }

        // Apply r-th round transformation.
        for i := 0; i < 8; i++ {
            L[i] = C0[byte(state[i%8]>>56)] ^
                C1[byte(state[(i+7)%8]>>48)] ^
                C2[byte(state[(i+6)%8]>>40)] ^
                C3[byte(state[(i+5)%8]>>32)] ^
                C4[byte(state[(i+4)%8]>>24)] ^
                C5[byte(state[(i+3)%8]>>16)] ^
                C6[byte(state[(i+2)%8]>>8)] ^
                C7[byte(state[(i+1)%8])] ^
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
