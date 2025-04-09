package mode

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * An implementation of the CBC mode for GOST 3412 2015 cipher.
 * See  <a href="https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
type g3413cbc struct {
    b         cipher.Block
    blockSize int
    iv        []byte
}

func newG3413CBC(b cipher.Block, iv []byte) *g3413cbc {
    blockSize := b.BlockSize()
    if len(iv) != 2*blockSize {
        panic("go-cryptobin/g3413cbc.newG3413CBC: IV length must equal two block size")
    }

    x := &g3413cbc{
        b:         b,
        blockSize: blockSize,
        iv:        make([]byte, 2*blockSize),
    }

    copy(x.iv, iv)

    return x
}

type g3413cbcEncrypter g3413cbc

// g3413cbcEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC encryption, like crypto/aes.
// NewG3413CBCEncrypter will check for this interface and return the specific
// cipher.BlockMode if found.
type g3413cbcEncAble interface {
    NewG3413CBCEncrypter(iv []byte) cipher.BlockMode
}

// NewG3413CBCEncrypter returns a cipher.BlockMode which encrypts in cipher block chaining
// mode, using the given cipher.Block. The length of iv must be the same as the
// Block's block size.
func NewG3413CBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != 2*b.BlockSize() {
        panic("go-cryptobin/g3413cbc.NewG3413CBCEncrypter: IV length must equal two block size")
    }
    if cbc, ok := b.(g3413cbcEncAble); ok {
        return cbc.NewG3413CBCEncrypter(iv)
    }
    return (*g3413cbcEncrypter)(newG3413CBC(b, iv))
}

// newG3413CBCGenericEncrypter returns a cipher.BlockMode which encrypts in cipher block chaining
// mode, using the given cipher.Block. The length of iv must be the same as the
// Block's block size. This always returns the generic non-asm encrypter for use
// in fuzz testing.
func newG3413CBCGenericEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != 2*b.BlockSize() {
        panic("go-cryptobin/g3413cbc.NewG3413CBCEncrypter: IV length must equal two block size")
    }
    return (*g3413cbcEncrypter)(newG3413CBC(b, iv))
}

func (x *g3413cbcEncrypter) BlockSize() int { return x.blockSize }

func (x *g3413cbcEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("go-cryptobin/g3413cbc: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("go-cryptobin/g3413cbc: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/g3413cbc: invalid buffer overlap")
    }

    iv := x.iv

    for len(src) > 0 {
        // Write the xor to dst, then encrypt in place.
        subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv[:x.blockSize])
        x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

        // Move to the next block with this block as the next iv.
        copy(iv, iv[x.blockSize:])
        copy(iv[x.blockSize:], dst[:x.blockSize])

        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }

    // Save the iv for the next CryptBlocks call.
    copy(x.iv, iv)
}

func (x *g3413cbcEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("go-cryptobin/g3413cbc: incorrect length IV")
    }
    copy(x.iv, iv)
}

type g3413cbcDecrypter g3413cbc

// g3413cbcDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC decryption, like crypto/aes.
// NewG3413CBCDecrypter will check for this interface and return the specific
// cipher.BlockMode if found.
type g3413cbcDecAble interface {
    NewG3413CBCDecrypter(iv []byte) cipher.BlockMode
}

// NewG3413CBCDecrypter returns a cipher.BlockMode which decrypts in cipher block chaining
// mode, using the given cipher.Block. The length of iv must be the same as the
// Block's block size and must match the iv used to encrypt the data.
func NewG3413CBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != 2*b.BlockSize() {
        panic("go-cryptobin/g3413cbc.NewG3413CBCDecrypter: IV length must equal two block size")
    }
    if cbc, ok := b.(g3413cbcDecAble); ok {
        return cbc.NewG3413CBCDecrypter(iv)
    }
    return (*g3413cbcDecrypter)(newG3413CBC(b, iv))
}

// newG3413CBCGenericDecrypter returns a cipher.BlockMode which encrypts in cipher block chaining
// mode, using the given cipher.Block. The length of iv must be the same as the
// Block's block size. This always returns the generic non-asm decrypter for use in
// fuzz testing.
func newG3413CBCGenericDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != 2*b.BlockSize() {
        panic("go-cryptobin/g3413cbc.NewG3413CBCDecrypter: IV length must equal two block size")
    }
    return (*g3413cbcDecrypter)(newG3413CBC(b, iv))
}

func (x *g3413cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *g3413cbcDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("go-cryptobin/g3413cbc: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("go-cryptobin/g3413cbc: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/g3413cbc: invalid buffer overlap")
    }
    if len(src) == 0 {
        return
    }

    // For each block, we need to xor the decrypted data with the previous block's ciphertext (the iv).
    // To avoid making a copy each time, we loop over the blocks BACKWARDS.
    end := len(src)
    start := end - x.blockSize

    if len(src) > x.blockSize {
        prev := start - x.blockSize

        if len(src) > x.blockSize * 2 {
            prev2Start := start - x.blockSize * 2
            prev2End := start - x.blockSize

            // Loop over all but the first block.
            for start > x.blockSize {
                x.b.Decrypt(dst[start:end], src[start:end])
                subtle.XORBytes(dst[start:end], dst[start:end], src[prev2Start:prev2End])

                end = start
                start = prev
                prev -= x.blockSize

                prev2Start -= x.blockSize
                prev2End -= x.blockSize
            }
        }

        // The first block is special because it uses the saved iv.
        x.b.Decrypt(dst[start:end], src[start:end])
        subtle.XORBytes(dst[start:end], dst[start:end], x.iv[x.blockSize:])

        end = start
        start = prev
    }

    x.b.Decrypt(dst[start:end], src[start:end])
    subtle.XORBytes(dst[start:end], dst[start:end], x.iv[:x.blockSize])
}

func (x *g3413cbcDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("go-cryptobin/g3413cbc: incorrect length IV")
    }
    copy(x.iv, iv)
}
