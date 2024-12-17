package cascade

import (
    "errors"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
    "github.com/deatil/go-cryptobin/tool/math/lcm"
)

type cascadeCipher struct {
    cipher1 cipher.Block
    cipher2 cipher.Block
    bs      int
}

// New creates and returns a new cipher.Block.
func NewCipher(cip1, cip2 cipher.Block) (cipher.Block, error) {
    c := new(cascadeCipher)
    c.cipher1 = cip1
    c.cipher2 = cip2
    c.bs = int(lcm.Lcm(int64(cip1.BlockSize()), int64(cip2.BlockSize())))

    if !(c.bs % cip1.BlockSize() == 0 &&
        c.bs % cip2.BlockSize() == 0) {
        return nil, errors.New("Combined block size is a multiple of each ciphers block")
    }

    return c, nil
}

func (this *cascadeCipher) BlockSize() int {
    return this.bs
}

func (this *cascadeCipher) Encrypt(dst, src []byte) {
    bs := this.bs

    if len(src) < bs {
        panic("go-cryptobin/cascade: input not full block")
    }

    if len(dst) < bs {
        panic("go-cryptobin/cascade: output not full block")
    }

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("go-cryptobin/cascade: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *cascadeCipher) Decrypt(dst, src []byte) {
    bs := this.bs

    if len(src) < bs {
        panic("go-cryptobin/cascade: input not full block")
    }

    if len(dst) < bs {
        panic("go-cryptobin/cascade: output not full block")
    }

    if alias.InexactOverlap(dst[:bs], src[:bs]) {
        panic("go-cryptobin/cascade: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *cascadeCipher) encrypt(dst, src []byte) {
    bs1 := this.cipher1.BlockSize()
    bs2 := this.cipher2.BlockSize()

    src = src[:this.bs]
    dst = dst[:this.bs]

    for i := 0; i < len(src); i += bs1 {
        this.cipher1.Encrypt(dst[i:i+bs1], src[i:i+bs1])
    }

    for i := 0; i < len(dst); i += bs2 {
        this.cipher2.Encrypt(dst[i:i+bs2], dst[i:i+bs2])
    }
}

func (this *cascadeCipher) decrypt(dst, src []byte) {
    bs1 := this.cipher1.BlockSize()
    bs2 := this.cipher2.BlockSize()

    src = src[:this.bs]
    dst = dst[:this.bs]

    for i := 0; i < len(dst); i += bs2 {
        this.cipher2.Decrypt(dst[i:i+bs2], src[i:i+bs2])
    }

    for i := 0; i < len(src); i += bs1 {
        this.cipher1.Decrypt(dst[i:i+bs1], dst[i:i+bs1])
    }
}
