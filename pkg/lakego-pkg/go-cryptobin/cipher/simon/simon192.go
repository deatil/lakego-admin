package simon

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type simonCipher192 struct {
   roundKey []uint64
}

// NewCipher192 creates and returns a new cipher.Block.
func NewCipher192(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 24:
            break
        default:
            return nil, KeySizeError(k)
    }

    c := new(simonCipher192)
    c.expandKey(key)

    return c, nil
}

func (this *simonCipher192) BlockSize() int {
    return BlockSize
}

func (this *simonCipher192) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/simon: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/simon: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/simon: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *simonCipher192) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/simon: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/simon: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/simon: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *simonCipher192) encrypt(out []byte, in []byte) {
    pt := keyToUint64s(in)

    x := pt[1]
    y := pt[0]

    var i int
    for i = 0; i < 68; i += 2 {
        y ^= f(x)
        y ^= this.roundKey[i]
        x ^= f(y)
        x ^= this.roundKey[i + 1]
    }

    y ^= f(x)
    y ^= this.roundKey[68]

    ct := uint64sToBytes([]uint64{x, y})
    copy(out, ct)
}

func (this *simonCipher192) decrypt(out []byte, in []byte) {
    ct := keyToUint64s(in)

    x := ct[0]
    y := ct[1]

    var i int
    for i = 68; i > 0; i -= 2 {
        y ^= f(x)
        y ^= this.roundKey[i]
        x ^= f(y)
        x ^= this.roundKey[i - 1]
    }

    y ^= f(x)
    y ^= this.roundKey[0]

    pt := uint64sToBytes([]uint64{y, x})
    copy(out, pt)
}

func (this *simonCipher192) expandKey(key []byte) {
    keys := keyToUint64s(key)

    w := make([]uint64, 69)

    w[0] = keys[0]
    w[1] = keys[1]
    w[2] = keys[2]
    w[3] = ks(w[2], w[0], 1)
    w[4] = ks(w[3], w[1], 1)
    w[5] = ks(w[4], w[2], 0)
    w[6] = ks(w[5], w[3], 1)
    w[7] = ks(w[6], w[4], 1)
    w[8] = ks(w[7], w[5], 0)
    w[9] = ks(w[8], w[6], 1)
    w[10] = ks(w[9], w[7], 1)
    w[11] = ks(w[10], w[8], 1)
    w[12] = ks(w[11], w[9], 0)
    w[13] = ks(w[12], w[10], 1)
    w[14] = ks(w[13], w[11], 0)
    w[15] = ks(w[14], w[12], 1)
    w[16] = ks(w[15], w[13], 1)
    w[17] = ks(w[16], w[14], 0)
    w[18] = ks(w[17], w[15], 0)
    w[19] = ks(w[18], w[16], 0)
    w[20] = ks(w[19], w[17], 1)
    w[21] = ks(w[20], w[18], 1)
    w[22] = ks(w[21], w[19], 0)
    w[23] = ks(w[22], w[20], 0)
    w[24] = ks(w[23], w[21], 1)
    w[25] = ks(w[24], w[22], 0)
    w[26] = ks(w[25], w[23], 1)
    w[27] = ks(w[26], w[24], 1)
    w[28] = ks(w[27], w[25], 1)
    w[29] = ks(w[28], w[26], 1)
    w[30] = ks(w[29], w[27], 0)
    w[31] = ks(w[30], w[28], 0)
    w[32] = ks(w[31], w[29], 0)
    w[33] = ks(w[32], w[30], 0)
    w[34] = ks(w[33], w[31], 0)
    w[35] = ks(w[34], w[32], 0)
    w[36] = ks(w[35], w[33], 1)
    w[37] = ks(w[36], w[34], 0)
    w[38] = ks(w[37], w[35], 0)
    w[39] = ks(w[38], w[36], 1)
    w[40] = ks(w[39], w[37], 0)
    w[41] = ks(w[40], w[38], 0)
    w[42] = ks(w[41], w[39], 0)
    w[43] = ks(w[42], w[40], 1)
    w[44] = ks(w[43], w[41], 0)
    w[45] = ks(w[44], w[42], 1)
    w[46] = ks(w[45], w[43], 0)
    w[47] = ks(w[46], w[44], 0)
    w[48] = ks(w[47], w[45], 1)
    w[49] = ks(w[48], w[46], 1)
    w[50] = ks(w[49], w[47], 1)
    w[51] = ks(w[50], w[48], 0)
    w[52] = ks(w[51], w[49], 0)
    w[53] = ks(w[52], w[50], 1)
    w[54] = ks(w[53], w[51], 1)
    w[55] = ks(w[54], w[52], 0)
    w[56] = ks(w[55], w[53], 1)
    w[57] = ks(w[56], w[54], 0)
    w[58] = ks(w[57], w[55], 0)
    w[59] = ks(w[58], w[56], 0)
    w[60] = ks(w[59], w[57], 0)
    w[61] = ks(w[60], w[58], 1)
    w[62] = ks(w[61], w[59], 1)
    w[63] = ks(w[62], w[60], 1)
    w[64] = ks(w[63], w[61], 1)
    w[65] = ks(w[64], w[62], 1)
    w[66] = ks(w[65], w[63], 1)
    w[67] = ks(w[66], w[64], 0)
    w[68] = ks(w[67], w[65], 1)

    this.roundKey = make([]uint64, 69)
    copy(this.roundKey, w)
}
