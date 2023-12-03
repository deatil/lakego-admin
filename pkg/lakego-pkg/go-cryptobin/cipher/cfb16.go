package cipher

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * cfb16 模式
 *
 * @create 2023-4-19
 * @author deatil
 */
type cfb16 struct {
    b       cipher.Block
    in      []byte
    out     []byte
    decrypt bool
}

func (x *cfb16) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/cfb16: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/cfb16: invalid buffer overlap")
    }

    bs := 2
    for i := 0; i < len(src); i += bs {
        x.b.Encrypt(x.out, x.in)

        end := i + bs
        if end > len(src) {
            end = len(src)
        }

        dstBytes := make([]byte, end-i)
        srcBytes := src[i:end]

        subtle.XORBytes(dstBytes, srcBytes, x.out[:])

        startIn := end - i
        copy(x.in, x.in[startIn:])

        if x.decrypt {
            copy(x.in[startIn:], srcBytes)
        } else {
            copy(x.in[startIn:], dstBytes)
        }

        copy(dst[i:end], dstBytes)
    }
}

func NewCFB16(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != blockSize {
        panic("cryptobin/cfb16: iv length must equal block size")
    }

    x := &cfb16{
        b:       block,
        in:      make([]byte, blockSize),
        out:     make([]byte, blockSize),
        decrypt: decrypt,
    }
    copy(x.in, iv)

    return x
}

func NewCFB16Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB16(block, iv, false)
}

func NewCFB16Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB16(block, iv, true)
}
