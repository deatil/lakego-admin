package mode

import (
    "bytes"
    "crypto/cipher"
)

type wrapPad struct {
    b         cipher.Block
    blockSize int
    iv        []byte
}

func newWrapPad(b cipher.Block, iv []byte) *wrapPad {
    c := &wrapPad{
        b:         b,
        blockSize: b.BlockSize(),
        iv:        make([]byte, b.BlockSize()),
    }

    if iv == nil {
        iv = defaultAiv
    }

    if len(iv) < 4 {
        panic("go-cryptobin/wrapPad: IV length must gt or equal 4 bytes")
    }

    copy(c.iv, iv)

    return c
}

type wrapPadEncrypter wrapPad

type wrapPadEncAble interface {
    NewWrapPadEncrypter(iv []byte) cipher.BlockMode
}

func NewWrapPadEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if wrapPad, ok := b.(wrapPadEncAble); ok {
        return wrapPad.NewWrapPadEncrypter(iv)
    }

    return (*wrapPadEncrypter)(newWrapPad(b, iv))
}

func (x *wrapPadEncrypter) BlockSize() int {
    return x.blockSize
}

/** Wrapping according to RFC 5649 section 4.1.
 *
 *  @param[in]  icv    (Non-standard) IV, 4 bytes. NULL = use default_aiv.
 *  @param[out] dst    Ciphertext. Minimal buffer length = (srclen + 15) bytes.
 *                     Input and output buffers can overlap if block function
 *                     supports that.
 *  @param[in]  src    Plaintext as n 64-bit blocks, n >= 2.
 */
func (x *wrapPadEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%8 != 0 {
        panic("go-cryptobin/wrapPad: input not full blocks")
    }

    if len(dst) < len(src)+8 {
        panic("go-cryptobin/wrapPad: output smaller than input")
    }

    icv := x.iv

    inlen := len(src)

    /* n: number of 64-bit blocks in the padded key data
     *
     * If length of plain text is not a multiple of 8, pad the plain text octet
     * string on the right with octets of zeros, where final length is the
     * smallest multiple of 8 that is greater than length of plain text.
     * If length of plain text is a multiple of 8, then there is no padding. */
    var blocks_padded = (inlen + 7) / 8 /* CEILING(m/8) */
    var padded_len = blocks_padded * 8

    /* RFC 5649 section 3: Alternative Initial Value */
    var aiv [8]byte

    /* Section 1: use 32-bit fixed field for plaintext octet length */
    if inlen == 0 || uint64(inlen) >= WRAP_MAX {
        return
    }

    /* Section 3: Alternative Initial Value */
    copy(aiv[:], icv[:4]);    /* Standard doesn't mention this. */

    aiv[4] = byte((inlen >> 24) & 0xFF)
    aiv[5] = byte((inlen >> 16) & 0xFF)
    aiv[6] = byte((inlen >> 8) & 0xFF)
    aiv[7] = byte(inlen & 0xFF)

    if len(dst) < (padded_len + len(aiv)) {
        panic("go-cryptobin/wrapPad: output too small")
    }

    if padded_len == 8 {
        /*
         * Section 4.1 - special case in step 2: If the padded plaintext
         * contains exactly eight octets, then prepend the AIV and encrypt
         * the resulting 128-bit block using AES in ECB mode.
         */
        copy(dst[8:], src)
        copy(dst, aiv[:8])

        x.b.Encrypt(dst, dst)
    } else {
        NewWrapEncrypter(x.b, aiv[:]).CryptBlocks(dst, src)
    }

    copy(x.iv, icv)
}

func (x *wrapPadEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("go-cryptobin/wrapPad: incorrect length IV")
    }

    copy(x.iv, iv)
}

type wrapPadDecrypter wrapPad

type wrapPadDecAble interface {
    NewWrapPadDecrypter(iv []byte) cipher.BlockMode
}

func NewWrapPadDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if wrapPad, ok := b.(wrapPadDecAble); ok {
        return wrapPad.NewWrapPadDecrypter(iv)
    }

    return (*wrapPadDecrypter)(newWrapPad(b, iv))
}

func (x *wrapPadDecrypter) BlockSize() int {
    return x.blockSize
}

/** Unwrapping according to RFC 5649 section 4.2.
 *
 *  @param[in]  icv    (Non-standard) IV, 4 bytes. NULL = use default_aiv.
 *  @param[out] dst    Plaintext. Minimal buffer length = (srclen - 8) bytes.
 *                     Input and output buffers can overlap if block function
 *                     supports that.
 *  @param[in]  src    Ciphertext as n 64-bit blocks.
 */
func (x *wrapPadDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%8 != 0 {
        panic("go-cryptobin/wrapPad: input not full blocks")
    }

    if len(dst) < len(src)-8 {
        panic("go-cryptobin/wrapPad: output smaller than input")
    }

    if len(src) == 0 {
        return
    }

    icv := x.iv
    inlen := len(src)

    empty := make([]byte, inlen-8)

    /* n: number of 64-bit blocks in the padded key data */
    var n int = inlen / 8 - 1
    var padded_len int
    var padding_len int
    var ptext_len uint32

    /* RFC 5649 section 3: Alternative Initial Value */
    var aiv [8]byte = [8]byte{}
    var zeros [8]byte = [8]byte{}

    /* Section 4.2: Ciphertext length has to be (n+1) 64-bit blocks. */
    if (((inlen & 0x7) != 0) || (inlen < 16) || (uint64(inlen) > WRAP_MAX)) {
        return
    }

    if inlen == 16 {
        /*
         * Section 4.2 - special case in step 1: When n=1, the ciphertext
         * contains exactly two 64-bit blocks and they are decrypted as a
         * single AES block using AES in ECB mode: AIV | P[1] = DEC(K, C[0] |
         * C[1])
         */
        var buff [16]byte

        x.b.Decrypt(buff[:], src)

        copy(aiv[:], buff[:8])
        /* Remove AIV */
        copy(dst, buff[8:16])
    } else {
        padded_len = inlen - 8

        iv := make([]byte, 8)
        wd := NewWrapDecrypter(x.b, iv)

        retiv, err := wd.(*wrapDecrypter).cryptBlocks(dst, src)
        if err != nil {
            copy(dst, empty)
            return
        }

        copy(aiv[:], retiv)
    }

    /*
     * Section 3: AIV checks: Check that MSB(32,A) = A65959A6. Optionally a
     * user-supplied value can be used (even if standard doesn't mention
     * this).
     */
    if !bytes.Equal(aiv[:4], icv[:4]) {
        copy(dst, empty)
        return
    }

    /*
     * Check that 8*(n-1) < LSB(32,AIV) <= 8*n. If so, let ptext_len =
     * LSB(32,AIV).
     */

    ptext_len = (uint32(aiv[4]) << 24) |
                (uint32(aiv[5]) << 16) |
                (uint32(aiv[6]) <<  8) |
                 uint32(aiv[7])
    if (8 * (uint32(n) - 1) >= ptext_len || ptext_len > 8 * uint32(n)) {
        copy(dst, empty)
        return
    }

    /*
     * Check that the rightmost padding_len octets of the output data are
     * zero.
     */
    padding_len = padded_len - int(ptext_len)
    if len(dst) > int(ptext_len) && bytes.Equal(dst[ptext_len:], zeros[:padding_len]) {
        copy(dst, empty)
        return
    }

    copy(x.iv, icv)
}

func (x *wrapPadDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("go-cryptobin/wrapPad: incorrect length IV")
    }

    copy(x.iv, iv)
}
