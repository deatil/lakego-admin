package mode

import (
    "fmt"
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * An implementation of the CFB mode for GOST 3412 2015 cipher.
 * See  <a href="https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
type g3413cfb struct {
    b       cipher.Block
    next    []byte
    out     []byte
    outUsed int
    s       int
    m       int

    decrypt bool
}

func (x *g3413cfb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/g3413cfb: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/g3413cfb: invalid buffer overlap")
    }

    bs := x.b.BlockSize()

    for len(src) > 0 {
        if x.outUsed == x.s {
            x.b.Encrypt(x.out, x.next[:bs])

            x.outUsed = 0
        }

        n := subtle.XORBytes(dst, src, x.out[x.outUsed:x.outUsed+x.s])

        copy(x.next, x.next[x.outUsed+x.s:])
        if !x.decrypt {
            copy(x.next[x.outUsed+(x.m - x.s):], dst)
        } else {
            copy(x.next[x.outUsed+(x.m - x.s):], src)
        }

        dst = dst[n:]
        src = src[n:]

        x.outUsed += n
    }
}

// NewG3413CFBEncrypter returns a Stream which encrypts with cipher feedback mode,
// using the given cipher.Block. The iv must be the same length as the cipher.Block's block
// size.
func NewG3413CFBEncrypter(block cipher.Block, iv []byte) cipher.Stream {
    return newG3413CFB(block, iv, block.BlockSize() * 8, false)
}

func NewG3413CFBEncrypterWithBitBlockSize(block cipher.Block, iv []byte, bitBlockSize int) cipher.Stream {
    return newG3413CFB(block, iv, bitBlockSize, false)
}

// NewG3413CFBDecrypter returns a Stream which decrypts with cipher feedback mode,
// using the given cipher.Block. The iv must be the same length as the cipher.Block's block
// size.
func NewG3413CFBDecrypter(block cipher.Block, iv []byte) cipher.Stream {
    return newG3413CFB(block, iv, block.BlockSize() * 8, true)
}

func NewG3413CFBDecrypterWithBitBlockSize(block cipher.Block, iv []byte, bitBlockSize int) cipher.Stream {
    return newG3413CFB(block, iv, bitBlockSize, true)
}

func newG3413CFB(block cipher.Block, iv []byte, bitBlockSize int, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != 2*blockSize {
        // stack trace will indicate whether it was de or encryption
        panic("go-cryptobin/g3413cfb.newG3413CFB: IV length must equal two block size")
    }

    if bitBlockSize < 0 || bitBlockSize > blockSize * 8 {
        panic(fmt.Sprintf("go-cryptobin/g3413cfb: Parameter bitBlockSize must be in range 0 < bitBlockSize <= %d", blockSize * 8))
    }

    s := bitBlockSize / 8

    x := &g3413cfb{
        b:       block,
        out:     make([]byte, blockSize),
        next:    make([]byte, 2*blockSize),
        outUsed: s,
        s:       s,
        m:       2*blockSize,
        decrypt: decrypt,
    }

    copy(x.next, iv)

    return x
}
