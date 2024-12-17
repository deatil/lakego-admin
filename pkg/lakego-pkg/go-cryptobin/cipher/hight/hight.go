package hight

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const (
    BlockSize = 8
    KeySize   = 16
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/hight: invalid key size %d", int(k))
}

type hightCipher struct {
    roundKey [136]byte
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    l := len(key)
    if l != KeySize {
        return nil, KeySizeError(l)
    }

    c := new(hightCipher)
    c.expandKey(key)

    return c, nil
}

func (this *hightCipher) BlockSize() int {
    return BlockSize
}

func (this *hightCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/hight: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/hight: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/hight: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *hightCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/hight: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/hight: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/hight: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *hightCipher) encryptStep(XX []byte, k, i0, i1, i2, i3, i4, i5, i6, i7 int) {
    XX[i0] = (XX[i0] ^ (f0[XX[i1]] + this.roundKey[4*k+3]))
    XX[i2] = (XX[i2] + (f1[XX[i3]] ^ this.roundKey[4*k+2]))
    XX[i4] = (XX[i4] ^ (f0[XX[i5]] + this.roundKey[4*k+1]))
    XX[i6] = (XX[i6] + (f1[XX[i7]] ^ this.roundKey[4*k+0]))
}

func (this *hightCipher) encrypt(dst, src []byte) {
    XX := []byte{
        src[0] + this.roundKey[0],
        src[1],
        src[2] ^ this.roundKey[1],
        src[3],
        src[4] + this.roundKey[2],
        src[5],
        src[6] ^ this.roundKey[3],
        src[7],
    }

    var j = 0;
    for i := 2; i <= 33; i++ {
        this.encryptStep(XX, i, 7-j%8, 7-(j+1)%8, 7-(j+2)%8, 7-(j+3)%8, 7-(j+4)%8, 7-(j+5)%8, 7-(j+6)%8, 7-(j+7)%8)
        j++
    }

    dst[0] = XX[1] + this.roundKey[4]
    dst[1] = XX[2]
    dst[2] = XX[3] ^ this.roundKey[5]
    dst[3] = XX[4]
    dst[4] = XX[5] + this.roundKey[6]
    dst[5] = XX[6]
    dst[6] = XX[7] ^ this.roundKey[7]
    dst[7] = XX[0]
}

func (this *hightCipher) decryptStep(XX []byte, k, i0, i1, i2, i3, i4, i5, i6, i7 int) {
    XX[i1] = (XX[i1] - (f1[XX[i2]] ^ this.roundKey[4*k+2]))
    XX[i3] = (XX[i3] ^ (f0[XX[i4]] + this.roundKey[4*k+1]))
    XX[i5] = (XX[i5] - (f1[XX[i6]] ^ this.roundKey[4*k+0]))
    XX[i7] = (XX[i7] ^ (f0[XX[i0]] + this.roundKey[4*k+3]))
}

func (this *hightCipher) decrypt(dst, src []byte) {
    XX := []byte{
        src[7],
        src[0] - this.roundKey[4],
        src[1],
        src[2] ^ this.roundKey[5],
        src[3],
        src[4] - this.roundKey[6],
        src[5],
        src[6] ^ this.roundKey[7],
    }

    var j = 0;
    for i := 33; i >= 2; i-- {
        this.decryptStep(XX, i, (7+j)%8, (6+j)%8, (5+j)%8, (4+j)%8, (3+j)%8, (2+j)%8, (1+j)%8, j%8)
        j++
    }

    dst[0] = XX[0] - this.roundKey[0]
    dst[1] = XX[1]
    dst[2] = XX[2] ^ this.roundKey[1]
    dst[3] = XX[3]
    dst[4] = XX[4] - this.roundKey[2]
    dst[5] = XX[5]
    dst[6] = XX[6] ^ this.roundKey[3]
    dst[7] = XX[7]
}

func (this *hightCipher) expandKey(key []byte) {
    for i := 0; i < 4; i++ {
        this.roundKey[i+0] = key[i+12]
        this.roundKey[i+4] = key[i+0]
    }

    for i := 0; i < 8; i++ {
        for k := 0; k < 8; k++ {
            this.roundKey[8+16*i+k+0] = key[((k-i)&7)+0] + delta[16*i+k+0]
        }

        for k := 0; k < 8; k++ {
            this.roundKey[8+16*i+k+8] = key[((k-i)&7)+8] + delta[16*i+k+8]
        }
    }
}
