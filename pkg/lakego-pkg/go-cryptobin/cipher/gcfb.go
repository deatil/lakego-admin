package cipher

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

var gcfbC = []byte{
    0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
    0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
    0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
    0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

type GCFBCipherFunc = func([]byte) (cipher.Block, error)

/**
 * An implementation of the GOST CFB mode with CryptoPro key meshing as described in RFC 4357.
 */
type gcfb struct {
    b         GCFBCipherFunc
    cfbEngine cipher.Stream
    key       []byte
    iv        []byte
    bs        int
    counter   int

    decrypt   bool
}

func (x *gcfb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/gcfb: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/gcfb: invalid buffer overlap")
    }

    for len(src) > 0 {
        if x.counter > 0 && x.counter % 1024 == 0 {
            base, err := x.b(x.key)
            if err != nil {
                panic(err)
            }

            nextKey := make([]byte, 32)

            base.Encrypt(nextKey[0:8], gcfbC[0:8])
            base.Encrypt(nextKey[8:16], gcfbC[8:16])
            base.Encrypt(nextKey[16:24], gcfbC[16:24])
            base.Encrypt(nextKey[24:32], gcfbC[24:32])

            copy(x.key, nextKey)

            base, err = x.b(nextKey)
            if err != nil {
                panic(err)
            }

            base.Encrypt(x.iv, x.iv)

            nb, err := x.b(nextKey)
            if err != nil {
                panic(err)
            }

            if x.decrypt {
                x.cfbEngine = cipher.NewCFBDecrypter(nb, x.iv)
            } else {
                x.cfbEngine = cipher.NewCFBEncrypter(nb, x.iv)
            }
        }

        x.cfbEngine.XORKeyStream(dst[:x.bs], src[:x.bs])

        dst = dst[x.bs:]
        src = src[x.bs:]

        x.counter += x.bs
    }
}

// NewGCFBEncrypter returns a Stream which encrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewGCFBEncrypter(block GCFBCipherFunc, key, iv []byte) cipher.Stream {
    return newGCFB(block, key, iv, false)
}

// NewGCFBDecrypter returns a Stream which decrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewGCFBDecrypter(block GCFBCipherFunc, key, iv []byte) cipher.Stream {
    return newGCFB(block, key, iv, true)
}

func newGCFB(block GCFBCipherFunc, key, iv []byte, decrypt bool) cipher.Stream {
    cip, err := block(key)
    if err != nil {
        panic("cryptobin/gcfb.newGCFB: invalid block")
    }

    blockSize := cip.BlockSize()
    if len(iv) != blockSize {
        // stack trace will indicate whether it was de or encryption
        panic("cryptobin/gcfb.newGCFB: IV length must equal block size")
    }

    x := &gcfb{
        b:       block,
        key:     make([]byte, len(key)),
        iv:      make([]byte, blockSize),
        bs:      blockSize,
        counter: 0,
        decrypt: decrypt,
    }

    if x.decrypt {
        x.cfbEngine = cipher.NewCFBDecrypter(cip, iv)
    } else {
        x.cfbEngine = cipher.NewCFBEncrypter(cip, iv)
    }

    copy(x.key, key)
    copy(x.iv, iv)

    return x
}
