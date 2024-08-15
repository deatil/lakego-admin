package gcm

import (
    "crypto/subtle"
    "encoding/binary"
)

func gcmInitGo(g *GCM, cipher Block) {
    var key [GCMBlockSize]byte
    cipher.Encrypt(key[:], key[:])

    // We precompute 16 multiples of |key|. However, when we do lookups
    // into this table we'll be using bits from a field element and
    // therefore the bits will be in the reverse order. So normally one
    // would expect, say, 4*key to be in index 4 of the table but due to
    // this bit ordering it will actually be in index 0010 (base 2) = 2.
    x := GCMFieldElement{
        binary.BigEndian.Uint64(key[:8]),
        binary.BigEndian.Uint64(key[8:]),
    }
    g.productTable[reverseBits(1)] = x

    for i := 2; i < 16; i += 2 {
        g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
        g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
    }
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
    i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
    return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
func gcmAdd(x, y *GCMFieldElement) GCMFieldElement {
    // Addition in a characteristic 2 field is just XOR.
    return GCMFieldElement{x.Low ^ y.Low, x.High ^ y.High}
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
func gcmDouble(x *GCMFieldElement) (double GCMFieldElement) {
    msbSet := x.High&1 == 1

    // Because of the bit-ordering, doubling is actually a right shift.
    double.High = x.High >> 1
    double.High |= x.Low << 63
    double.Low = x.Low >> 1

    // If the most-significant bit was set before shifting then it,
    // conceptually, becomes a term of x^128. This is greater than the
    // irreducible polynomial so the result has to be reduced. The
    // irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
    // eliminate the term at x^128 which also means subtracting the other
    // four terms. In characteristic 2 fields, subtraction == addition ==
    // XOR.
    if msbSet {
        double.Low ^= 0xe100000000000000
    }

    return
}

var gcmReductionTable = []uint16{
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// Mul sets y to y*H, where H is the GCM key, fixed during NewGCMWithNonceSize.
func gcmMul(g *GCM, y *GCMFieldElement) {
    var z GCMFieldElement

    for i := 0; i < 2; i++ {
        word := y.High
        if i == 1 {
            word = y.Low
        }

        // Multiplication works by multiplying z by 16 and adding in
        // one of the precomputed multiples of H.
        for j := 0; j < 64; j += 4 {
            msw := z.High & 0xf
            z.High >>= 4
            z.High |= z.Low << 60
            z.Low >>= 4
            z.Low ^= uint64(gcmReductionTable[msw]) << 48

            // the values in |table| are ordered for
            // little-endian bit positions. See the comment
            // in NewGCMWithNonceSize.
            t := &g.productTable[word&0xf]

            z.Low ^= t.Low
            z.High ^= t.High
            word >>= 4
        }
    }

    *y = z
}

// UpdateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func gcmUpdateBlocksGo(g *GCM, y *GCMFieldElement, blocks []byte) {
    for len(blocks) > 0 {
        y.Low ^= binary.BigEndian.Uint64(blocks)
        y.High ^= binary.BigEndian.Uint64(blocks[8:])
        gcmMul(g, y)
        blocks = blocks[GCMBlockSize:]
    }
}

// update extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
func gcmUpdateGo(g *GCM, y *GCMFieldElement, data []byte) {
    fullBlocks := (len(data) >> 4) << 4
    gcmUpdateBlocksGo(g, y, data[:fullBlocks])

    if len(data) != fullBlocks {
        var partialBlock [GCMBlockSize]byte
        copy(partialBlock[:], data[fullBlocks:])
        gcmUpdateBlocksGo(g, y, partialBlock[:])
    }
}

// deriveCounter computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
func gcmDeriveCounterGo(g *GCM, counter *[GCMBlockSize]byte, nonce []byte) {
    // GCM has two modes of operation with respect to the initial counter
    // state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
    // for nonces of other lengths. For a 96-bit nonce, the nonce, along
    // with a four-byte big-endian counter starting at one, is used
    // directly as the starting counter. For other nonce sizes, the counter
    // is computed by passing it through the GHASH function.
    if len(nonce) == GCMStandardNonceSize {
        copy(counter[:], nonce)
        counter[GCMBlockSize-1] = 1
    } else {
        var y GCMFieldElement
        gcmUpdateGo(g, &y, nonce)
        y.High ^= uint64(len(nonce)) * 8
        gcmMul(g, &y)
        binary.BigEndian.PutUint64(counter[:8], y.Low)
        binary.BigEndian.PutUint64(counter[8:], y.High)
    }
}

// auth calculates GHASH(ciphertext, additionalData), masks the result with
// tagMask and writes the result to out.
func gcmAuthGo(g *GCM, out, ciphertext, additionalData []byte, tagMask *[GCMTagSize]byte) {
    var y GCMFieldElement
    gcmUpdateGo(g, &y, additionalData)
    gcmUpdateGo(g, &y, ciphertext)

    gcmFinishGo(g, out, &y, len(ciphertext), len(additionalData), tagMask)
}

func gcmFinishGo(g *GCM, out []byte, y *GCMFieldElement, ciphertextLen, additionalDataLen int, tagMask *[GCMTagSize]byte) {
    y.Low ^= uint64(additionalDataLen) * 8
    y.High ^= uint64(ciphertextLen) * 8

    gcmMul(g, y)

    binary.BigEndian.PutUint64(out, y.Low)
    binary.BigEndian.PutUint64(out[8:], y.High)

    subtle.XORBytes(out, out, tagMask[:])
}
