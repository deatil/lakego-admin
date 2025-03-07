// CFB (Cipher Feedback) Mode.
package mode

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type cfb struct {
    b       cipher.Block
    next    []byte
    out     []byte
    outUsed int

    decrypt bool
}

func (x *cfb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/cfb: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/cfb: invalid buffer overlap")
    }

    for len(src) > 0 {
        if x.outUsed == len(x.out) {
            x.b.Encrypt(x.out, x.next)
            x.outUsed = 0
        }

        if x.decrypt {
            // We can precompute a larger segment of the
            // keystream on decryption. This will allow
            // larger batches for xor, and we should be
            // able to match CTR/OFB performance.
            copy(x.next[x.outUsed:], src)
        }

        n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
        if !x.decrypt {
            copy(x.next[x.outUsed:], dst)
        }

        dst = dst[n:]
        src = src[n:]
        x.outUsed += n
    }
}

// NewCFBEncrypter returns a Stream which encrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewCFBEncrypter(block cipher.Block, iv []byte) cipher.Stream {
    return newCFB(block, iv, false)
}

// NewCFBDecrypter returns a Stream which decrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream {
    return newCFB(block, iv, true)
}

func newCFB(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != blockSize {
        // stack trace will indicate whether it was de or encryption
        panic("cipher.newCFB: IV length must equal block size")
    }

    x := &cfb{
        b:       block,
        out:     make([]byte, blockSize),
        next:    make([]byte, blockSize),
        outUsed: blockSize,
        decrypt: decrypt,
    }
    copy(x.next, iv)

    return x
}
