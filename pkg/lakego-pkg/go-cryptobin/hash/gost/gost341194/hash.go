package gost341194

import (
    "math/big"
    "crypto/cipher"
    "encoding/binary"
)

// GOST R 34.11-94 hash function.
// RFC 5831.

const (
    Size      = 32
    BlockSize = 32
)

var (
    c2 = [BlockSize]byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }
    c3 = [BlockSize]byte{
        0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff,
        0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
        0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
        0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
    }
    c4 = [BlockSize]byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }

    big256 = big.NewInt(0).SetBit(big.NewInt(0), 256, 1)
)

type digest struct {
    cipher func([]byte) cipher.Block
    size   uint64
    hsh    [BlockSize]byte
    chk    *big.Int
    buf    []byte
    tmp    [BlockSize]byte
}

func New(cipher func([]byte) cipher.Block) *digest {
    h := &digest{
        cipher: cipher,
    }
    h.Reset()

    return h
}

func (h *digest) Size() int {
    return Size
}

func (h *digest) BlockSize() int {
    return BlockSize
}

func (h *digest) Reset() {
    h.size = 0
    h.hsh = [BlockSize]byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }
    h.chk = big.NewInt(0)
    h.buf = h.buf[:0]
}

func (h *digest) Write(data []byte) (int, error) {
    h.buf = append(h.buf, data...)

    for len(h.buf) >= BlockSize {
        h.size += BlockSize * 8
        blockReverse(h.tmp[:], h.buf[:BlockSize])
        h.chk = h.chkAdd(h.tmp[:])
        h.buf = h.buf[BlockSize:]
        h.hsh = h.step(h.hsh, h.tmp)
    }

    return len(data), nil
}

func (h *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *h
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (h *digest) checkSum() [Size]byte {
    size := h.size
    chk := h.chk
    hsh := h.hsh
    block := new([BlockSize]byte)

    if len(h.buf) != 0 {
        size += uint64(len(h.buf)) * 8
        copy(block[:], h.buf)
        blockReverse(block[:], block[:])
        chk = h.chkAdd(block[:])
        hsh = h.step(hsh, *block)
        block = new([BlockSize]byte)
    }

    binary.BigEndian.PutUint64(block[24:], size)
    hsh = h.step(hsh, *block)
    block = new([BlockSize]byte)
    chkBytes := chk.Bytes()

    copy(block[BlockSize-len(chkBytes):], chkBytes)

    hsh = h.step(hsh, *block)
    blockReverse(hsh[:], hsh[:])

    return hsh
}

func fA(in *[BlockSize]byte) *[BlockSize]byte {
    out := new([BlockSize]byte)
    out[0] = in[16+0] ^ in[24+0]
    out[1] = in[16+1] ^ in[24+1]
    out[2] = in[16+2] ^ in[24+2]
    out[3] = in[16+3] ^ in[24+3]
    out[4] = in[16+4] ^ in[24+4]
    out[5] = in[16+5] ^ in[24+5]
    out[6] = in[16+6] ^ in[24+6]
    out[7] = in[16+7] ^ in[24+7]
    copy(out[8:], in[0:24])
    return out
}

func fP(in *[BlockSize]byte) *[BlockSize]byte {
    return &[BlockSize]byte{
        in[0], in[8], in[16], in[24], in[1], in[9], in[17],
        in[25], in[2], in[10], in[18], in[26], in[3],
        in[11], in[19], in[27], in[4], in[12], in[20],
        in[28], in[5], in[13], in[21], in[29], in[6],
        in[14], in[22], in[30], in[7], in[15], in[23], in[31],
    }
}

func fChi(in *[BlockSize]byte) *[BlockSize]byte {
    out := new([BlockSize]byte)
    out[0] = in[32-2] ^ in[32-4] ^ in[32-6] ^ in[32-8] ^ in[32-32] ^ in[32-26]
    out[1] = in[32-1] ^ in[32-3] ^ in[32-5] ^ in[32-7] ^ in[32-31] ^ in[32-25]
    copy(out[2:32], in[0:30])
    return out
}

func blockReverse(dst, src []byte) {
    for i, j := 0, BlockSize-1; i < j; i, j = i+1, j-1 {
        dst[i], dst[j] = src[j], src[i]
    }
}

func blockXor(dst, a, b *[BlockSize]byte) {
    for i := 0; i < BlockSize; i++ {
        dst[i] = a[i] ^ b[i]
    }
}

func (h *digest) step(hin, m [BlockSize]byte) [BlockSize]byte {
    out := new([BlockSize]byte)
    u := new([BlockSize]byte)
    v := new([BlockSize]byte)
    k := new([BlockSize]byte)

    (*u) = hin
    (*v) = m

    blockXor(k, u, v)
    k = fP(k)
    blockReverse(k[:], k[:])

    c := h.cipher(k[:])

    s := make([]byte, c.BlockSize())
    c.Encrypt(s, []byte{
        hin[31], hin[30], hin[29], hin[28],
        hin[27], hin[26], hin[25], hin[24],
    })

    out[31] = s[0]
    out[30] = s[1]
    out[29] = s[2]
    out[28] = s[3]
    out[27] = s[4]
    out[26] = s[5]
    out[25] = s[6]
    out[24] = s[7]

    blockXor(u, fA(u), &c2)
    v = fA(fA(v))
    blockXor(k, u, v)
    k = fP(k)
    blockReverse(k[:], k[:])

    c = h.cipher(k[:])
    c.Encrypt(s, []byte{
        hin[23], hin[22], hin[21], hin[20],
        hin[19], hin[18], hin[17], hin[16],
    })

    out[23] = s[0]
    out[22] = s[1]
    out[21] = s[2]
    out[20] = s[3]
    out[19] = s[4]
    out[18] = s[5]
    out[17] = s[6]
    out[16] = s[7]

    blockXor(u, fA(u), &c3)
    v = fA(fA(v))
    blockXor(k, u, v)
    k = fP(k)
    blockReverse(k[:], k[:])

    c = h.cipher(k[:])
    c.Encrypt(s, []byte{
        hin[15], hin[14], hin[13], hin[12],
        hin[11], hin[10], hin[9], hin[8],
    })

    out[15] = s[0]
    out[14] = s[1]
    out[13] = s[2]
    out[12] = s[3]
    out[11] = s[4]
    out[10] = s[5]
    out[9] = s[6]
    out[8] = s[7]

    blockXor(u, fA(u), &c4)
    v = fA(fA(v))
    blockXor(k, u, v)
    k = fP(k)
    blockReverse(k[:], k[:])

    c = h.cipher(k[:])
    c.Encrypt(s, []byte{
        hin[7], hin[6], hin[5], hin[4],
        hin[3], hin[2], hin[1], hin[0],
    })

    out[7] = s[0]
    out[6] = s[1]
    out[5] = s[2]
    out[4] = s[3]
    out[3] = s[4]
    out[2] = s[5]
    out[1] = s[6]
    out[0] = s[7]

    for i := 0; i < 12; i++ {
        out = fChi(out)
    }
    blockXor(out, out, &m)
    out = fChi(out)
    blockXor(out, out, &hin)
    for i := 0; i < 61; i++ {
        out = fChi(out)
    }
    return *out
}

func (h *digest) chkAdd(data []byte) *big.Int {
    i := big.NewInt(0).SetBytes(data)
    i.Add(i, h.chk)
    if i.Cmp(big256) != -1 {
        i.Sub(i, big256)
    }

    return i
}
