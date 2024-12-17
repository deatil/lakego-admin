package speck

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/speck: invalid key size %d", int(k))
}

type speckCipher struct {
   round int
   roundKey []uint64
}

// NewCipher creates and returns a new cipher.Block.
// speck128
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(speckCipher)
    c.expandKey(key)

    return c, nil
}

func (this *speckCipher) BlockSize() int {
    return BlockSize
}

func (this *speckCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/speck: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/speck: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/speck: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *speckCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/speck: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/speck: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/speck: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *speckCipher) encrypt(out []byte, in []byte) {
    pt := keyToUint64s(in)

    x := pt[1]
    y := pt[0]

    var i int
    for i = 0; i < this.round+1; i++ {
        x = rotater64(x, 8)
        x += y
        x ^= this.roundKey[i]
        y = rotatel64(y, 3)
        y ^= x;
    }

    ct := uint64sToBytes([]uint64{y, x})
    copy(out, ct)
}

func (this *speckCipher) decrypt(out []byte, in []byte) {
    ct := keyToUint64s(in)

    x := ct[1]
    y := ct[0]

    var i int
    for i = this.round; i >= 0; i-- {
        y ^= x
        y = rotater64(y, 3)
        x ^= this.roundKey[i]
        x -= y
        x = rotatel64(x, 8)
    }

    pt := uint64sToBytes([]uint64{y, x})
    copy(out, pt)
}

func (this *speckCipher) expandKey(key []byte) {
    keys := keyToUint64s(key)

    keyLen := len(key)
    switch keyLen {
        case 16:
            this.expandKey128(keys)
        case 24:
            this.expandKey192(keys)
        case 32:
            this.expandKey256(keys)
    }
}

func (this *speckCipher) expandKey128(keys []uint64) {
    this.round = 31

    w := make([]uint64, 32)
    w[0] = keys[0]

    x := keys[1]
    var y uint64

    ks(x, &y, w[0], &w[1], 0)
    ks(y, &x, w[1], &w[2], 1)
    ks(x, &y, w[2], &w[3], 2)
    ks(y, &x, w[3], &w[4], 3)
    ks(x, &y, w[4], &w[5], 4)
    ks(y, &x, w[5], &w[6], 5)
    ks(x, &y, w[6], &w[7], 6)
    ks(y, &x, w[7], &w[8], 7)
    ks(x, &y, w[8], &w[9], 8)
    ks(y, &x, w[9], &w[10], 9)
    ks(x, &y, w[10], &w[11], 10)
    ks(y, &x, w[11], &w[12], 11)
    ks(x, &y, w[12], &w[13], 12)
    ks(y, &x, w[13], &w[14], 13)
    ks(x, &y, w[14], &w[15], 14)
    ks(y, &x, w[15], &w[16], 15)
    ks(x, &y, w[16], &w[17], 16)
    ks(y, &x, w[17], &w[18], 17)
    ks(x, &y, w[18], &w[19], 18)
    ks(y, &x, w[19], &w[20], 19)
    ks(x, &y, w[20], &w[21], 20)
    ks(y, &x, w[21], &w[22], 21)
    ks(x, &y, w[22], &w[23], 22)
    ks(y, &x, w[23], &w[24], 23)
    ks(x, &y, w[24], &w[25], 24)
    ks(y, &x, w[25], &w[26], 25)
    ks(x, &y, w[26], &w[27], 26)
    ks(y, &x, w[27], &w[28], 27)
    ks(x, &y, w[28], &w[29], 28)
    ks(y, &x, w[29], &w[30], 29)
    ks(x, &y, w[30], &w[31], 30)

    this.roundKey = make([]uint64, len(w))
    copy(this.roundKey, w)
}

func (this *speckCipher) expandKey192(keys []uint64) {
    this.round = 32

    w := make([]uint64, 33)
    w[0] = keys[0]

    l := make([]uint64, 34)
    copy(l, keys[1:])

    var i uint64
    for i = 0; i < 32; i++ {
        l[i + 2] = (w[i] + rotater64(l[i], 8)) ^ i
        w[i + 1] = rotatel64(w[i], 3) ^ l[i + 2]
    }

    this.roundKey = make([]uint64, len(w))
    copy(this.roundKey, w)
}

func (this *speckCipher) expandKey256(keys []uint64) {
    this.round = 33

    w := make([]uint64, 34)
    w[0] = keys[0]

    l := make([]uint64, 36)
    copy(l, keys[1:])

    var i uint64
    for i = 0; i < 33; i++ {
        l[i + 3] = (w[i] + rotater64(l[i], 8)) ^ i
        w[i + 1] = rotatel64(w[i], 3) ^ l[i + 3]
    }

    this.roundKey = make([]uint64, len(w))
    copy(this.roundKey, w)
}
