package mode

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// ocfb mode
type ocfbEncrypter struct {
    b       cipher.Block
    fre     []byte
    outUsed int
}

// An OCFBResyncOption determines if the "resynchronization step" of OCFB is
// performed.
type OCFBResyncOption bool

const (
    OCFBResync   OCFBResyncOption = true
    OCFBNoResync OCFBResyncOption = false
)

// NewOCFBEncrypter returns a cipher.Stream which encrypts data with OpenPGP's
// cipher feedback mode using the given cipher.Block, and an initial amount of
// ciphertext.  randData must be random bytes and be the same length as the
// cipher.Block's block size. Resync determines if the "resynchronization step"
// from RFC 4880, 13.9 step 7 is performed. Different parts of OpenPGP vary on
// this point.
func NewOCFBEncrypter(block cipher.Block, randData []byte, resync OCFBResyncOption) (cipher.Stream, []byte) {
    blockSize := block.BlockSize()
    if len(randData) != blockSize {
        panic("go-cryptobin/ocfb.NewOCFBEncrypter: randData length must equal block size")
    }

    x := &ocfbEncrypter{
        b:       block,
        fre:     make([]byte, blockSize),
        outUsed: 0,
    }
    prefix := make([]byte, blockSize+2)

    block.Encrypt(x.fre, x.fre)
    for i := 0; i < blockSize; i++ {
        prefix[i] = randData[i] ^ x.fre[i]
    }

    block.Encrypt(x.fre, prefix[:blockSize])
    prefix[blockSize] = x.fre[0] ^ randData[blockSize-2]
    prefix[blockSize+1] = x.fre[1] ^ randData[blockSize-1]

    if resync {
        block.Encrypt(x.fre, prefix[2:])
    } else {
        x.fre[0] = prefix[blockSize]
        x.fre[1] = prefix[blockSize+1]
        x.outUsed = 2
    }

    return x, prefix
}

func (x *ocfbEncrypter) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/ocfb: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/ocfb: invalid buffer overlap")
    }

    for i := 0; i < len(src); i++ {
        if x.outUsed == len(x.fre) {
            x.b.Encrypt(x.fre, x.fre)
            x.outUsed = 0
        }

        x.fre[x.outUsed] ^= src[i]
        dst[i] = x.fre[x.outUsed]
        x.outUsed++
    }
}

type ocfbDecrypter struct {
    b       cipher.Block
    fre     []byte
    outUsed int
}

// NewOCFBDecrypter returns a cipher.Stream which decrypts data with OpenPGP's
// cipher feedback mode using the given cipher.Block. Prefix must be the first
// blockSize + 2 bytes of the ciphertext, where blockSize is the cipher.Block's
// block size. If an incorrect key is detected then nil is returned. On
// successful exit, blockSize+2 bytes of decrypted data are written into
// prefix. Resync determines if the "resynchronization step" from RFC 4880,
// 13.9 step 7 is performed. Different parts of OpenPGP vary on this point.
func NewOCFBDecrypter(block cipher.Block, prefix []byte, resync OCFBResyncOption) cipher.Stream {
    blockSize := block.BlockSize()
    if len(prefix) != blockSize+2 {
        panic("go-cryptobin/ocfb.NewOCFBDecrypter: prefix length must equal block size add two")
    }

    x := &ocfbDecrypter{
        b:       block,
        fre:     make([]byte, blockSize),
        outUsed: 0,
    }
    prefixCopy := make([]byte, len(prefix))
    copy(prefixCopy, prefix)

    block.Encrypt(x.fre, x.fre)
    for i := 0; i < blockSize; i++ {
        prefixCopy[i] ^= x.fre[i]
    }

    block.Encrypt(x.fre, prefix[:blockSize])
    prefixCopy[blockSize] ^= x.fre[0]
    prefixCopy[blockSize+1] ^= x.fre[1]

    if prefixCopy[blockSize-2] != prefixCopy[blockSize] ||
        prefixCopy[blockSize-1] != prefixCopy[blockSize+1] {
        panic("go-cryptobin/ocfb: invalid prefix overlap")
    }

    if resync {
        block.Encrypt(x.fre, prefix[2:])
    } else {
        x.fre[0] = prefix[blockSize]
        x.fre[1] = prefix[blockSize+1]
        x.outUsed = 2
    }
    copy(prefix, prefixCopy)
    return x
}

func (x *ocfbDecrypter) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/ocfb: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/ocfb: invalid buffer overlap")
    }

    for i := 0; i < len(src); i++ {
        if x.outUsed == len(x.fre) {
            x.b.Encrypt(x.fre, x.fre)
            x.outUsed = 0
        }

        c := src[i]
        dst[i] = x.fre[x.outUsed] ^ src[i]
        x.fre[x.outUsed] = c
        x.outUsed++
    }
}
