package hctr

import (
    "errors"
    "crypto/cipher"
    "crypto/subtle"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const blockSize = 16

type concurrentBlocks interface {
    Concurrency() int
    EncryptBlocks(dst, src []byte)
    DecryptBlocks(dst, src []byte)
}

type hctrFieldElement struct {
    low, high uint64
}

func reverseBits(i int) int {
    i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
    return i
}

func hctrAdd(x, y hctrFieldElement) hctrFieldElement {
    return hctrFieldElement{x.low ^ y.low, x.high ^ y.high}
}

func hctrDouble(x hctrFieldElement) (double hctrFieldElement) {
    msbSet := (x.high&1 == 1)

    double.high = x.high >> 1
    double.high |= x.low << 63
    double.low = x.low >> 1

    if msbSet {
        double.low ^= 0xe100000000000000
    }

    return
}

var hctrReductionTable = []uint16{
    0x0000, 0x1c20, 0x3840, 0x2460,
    0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

type hctr struct {
    cipher cipher.Block
    tweak  [blockSize]byte
    productTable [16]hctrFieldElement
}

func NewHCTR(cipher cipher.Block, tweak, hkey []byte) (*hctr, error) {
    if len(tweak) != blockSize || len(hkey) != blockSize {
        return nil, errors.New("cryptobin/hctr: invalid tweak and/or hash key length")
    }

    c := &hctr{}
    c.cipher = cipher

    copy(c.tweak[:], tweak)

    x := hctrFieldElement{
        binary.BigEndian.Uint64(hkey[:8]),
        binary.BigEndian.Uint64(hkey[8:]),
    }

    c.productTable[reverseBits(1)] = x

    for i := 2; i < 16; i += 2 {
        c.productTable[reverseBits(i)] = hctrDouble(c.productTable[reverseBits(i/2)])
        c.productTable[reverseBits(i+1)] = hctrAdd(c.productTable[reverseBits(i)], x)
    }

    return c, nil
}

func (h *hctr) BlockSize() int {
    return blockSize
}

func (h *hctr) mul(y *hctrFieldElement) {
    var z hctrFieldElement

    for i := 0; i < 2; i++ {
        word := y.high
        if i == 1 {
            word = y.low
        }

        for j := 0; j < 64; j += 4 {
            msw := z.high & 0xf

            z.high >>= 4
            z.high |= z.low << 60

            z.low >>= 4
            z.low ^= uint64(hctrReductionTable[msw]) << 48

            t := h.productTable[word&0xf]

            z.low ^= t.low
            z.high ^= t.high

            word >>= 4
        }
    }

    *y = z
}

func (h *hctr) updateBlock(block []byte, y *hctrFieldElement) {
    y.low ^= binary.BigEndian.Uint64(block)
    y.high ^= binary.BigEndian.Uint64(block[8:])

    h.mul(y)
}

func (h *hctr) uhash(m []byte, out []byte) {
    var y hctrFieldElement
    msg := m

    for len(msg) >= blockSize {
        h.updateBlock(msg, &y)

        msg = msg[blockSize:]
    }

    if len(msg) > 0 {
        var partialBlock [blockSize]byte

        copy(partialBlock[:], msg)
        copy(partialBlock[len(msg):], h.tweak[:])

        h.updateBlock(partialBlock[:], &y)

        copy(partialBlock[:], h.tweak[len(msg):])

        for i := len(msg); i < blockSize; i++ {
            partialBlock[i] = 0
        }

        h.updateBlock(partialBlock[:], &y)
    } else {
        h.updateBlock(h.tweak[:], &y)
    }

    y.high ^= uint64(len(m)+blockSize) * 8

    h.mul(&y)

    binary.BigEndian.PutUint64(out[:], y.low)
    binary.BigEndian.PutUint64(out[8:], y.high)
}

func (h *hctr) Encrypt(ciphertext, plaintext []byte) {
    if len(ciphertext) < len(plaintext) {
        panic("cryptobin/hctr: ciphertext is smaller than plaintext")
    }

    if len(plaintext) < blockSize {
        panic("cryptobin/hctr: plaintext length is smaller than the block size")
    }

    if alias.InexactOverlap(ciphertext[:len(plaintext)], plaintext) {
        panic("cryptobin/hctr: invalid buffer overlap")
    }

    var z1, z2 [blockSize]byte

    h.uhash(plaintext[blockSize:], z1[:])
    subtle.XORBytes(z1[:], z1[:], plaintext[:blockSize])

    h.cipher.Encrypt(z2[:], z1[:])

    subtle.XORBytes(z1[:], z1[:], z2[:])
    h.ctr(ciphertext[blockSize:], plaintext[blockSize:], z1[:])

    h.uhash(ciphertext[blockSize:], z1[:])
    subtle.XORBytes(ciphertext, z2[:], z1[:])
}

func (h *hctr) Decrypt(plaintext, ciphertext []byte) {
    if len(plaintext) < len(ciphertext) {
        panic("cryptobin/hctr: plaintext is smaller than cihpertext")
    }

    if len(ciphertext) < blockSize {
        panic("cryptobin/hctr: ciphertext length is smaller than the block size")
    }

    if alias.InexactOverlap(plaintext[:len(ciphertext)], ciphertext) {
        panic("cryptobin/hctr: invalid buffer overlap")
    }

    var z1, z2 [blockSize]byte

    h.uhash(ciphertext[blockSize:], z2[:])
    subtle.XORBytes(z2[:], z2[:], ciphertext[:blockSize])

    h.cipher.Decrypt(z1[:], z2[:])

    subtle.XORBytes(z2[:], z2[:], z1[:])
    h.ctr(plaintext[blockSize:], ciphertext[blockSize:], z2[:])

    h.uhash(plaintext[blockSize:], z2[:])
    subtle.XORBytes(plaintext, z2[:], z1[:])
}

func (h *hctr) ctr(dst, src []byte, baseCtr []byte) {
    ctr := make([]byte, blockSize)
    num := make([]byte, blockSize)
    i := uint64(1)

    if concCipher, ok := h.cipher.(concurrentBlocks); ok {
        batchSize := concCipher.Concurrency() * blockSize
        if len(src) >= batchSize {
            var ctrs []byte = make([]byte, batchSize)

            for len(src) >= batchSize {
                for j := 0; j < concCipher.Concurrency(); j++ {
                    binary.BigEndian.PutUint64(num[blockSize-8:], i)
                    subtle.XORBytes(ctrs[j*blockSize:], baseCtr, num)
                    i++
                }

                concCipher.EncryptBlocks(ctrs, ctrs)
                subtle.XORBytes(dst, src, ctrs)
                src = src[batchSize:]
                dst = dst[batchSize:]
            }
        }
    }

    for len(src) > 0 {
        binary.BigEndian.PutUint64(num[blockSize-8:], i)

        subtle.XORBytes(ctr, baseCtr, num)

        h.cipher.Encrypt(ctr, ctr)

        n := subtle.XORBytes(dst, src, ctr)

        src = src[n:]
        dst = dst[n:]

        i++
    }
}
