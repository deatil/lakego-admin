package mode

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * cfb64 模式
 *
 * @create 2023-4-19
 * @author deatil
 */
type cfb64 struct {
    b       cipher.Block
    in      []byte
    out     []byte
    decrypt bool
}

// 每个块都进行异或
func (x *cfb64) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/cfb64: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/cfb64: invalid buffer overlap")
    }

    bs := 8
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

func NewCFB64(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != blockSize {
        panic("go-cryptobin/cfb64: iv length must equal block size")
    }

    x := &cfb64{
        b:       block,
        in:      make([]byte, blockSize),
        out:     make([]byte, blockSize),
        decrypt: decrypt,
    }
    copy(x.in, iv)

    return x
}

func NewCFB64Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB64(block, iv, false)
}

func NewCFB64Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB64(block, iv, true)
}
