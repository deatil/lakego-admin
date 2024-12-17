package kasumi

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
    return fmt.Sprintf("go-cryptobin/kasumi: invalid key size %d", int(k))
}

type kasumiCipher struct {
    KLi1, KLi2 [8]uint16
    KOi1, KOi2, KOi3 [8]uint16
    KIi1, KIi2, KIi3 [8]uint16
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    l := len(key)
    if l != KeySize {
        return nil, KeySizeError(l)
    }

    c := new(kasumiCipher)
    c.KeySchedule(key)

    return c, nil
}

func (this *kasumiCipher) BlockSize() int {
    return BlockSize
}

func (this *kasumiCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/kasumi: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/kasumi: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/kasumi: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *kasumiCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/kasumi: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/kasumi: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/kasumi: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *kasumiCipher) encrypt(dst, src []byte) {
    var left, right, temp uint32

    var n int32

    left  = bytesToUint32(src[0:])
    right = bytesToUint32(src[4:])

    n = 0

    for n <= 7 {
        temp = this.FL(left, n)
        temp = this.FO(temp, n)
        n++

        right ^= temp

        temp = this.FO(right, n)
        temp = this.FL(temp, n)
        n++

        left ^= temp
    }

    leftBytes := uint32ToBytes(left)
    rightBytes := uint32ToBytes(right)

    copy(dst[0:], leftBytes)
    copy(dst[4:], rightBytes)
}

func (this *kasumiCipher) decrypt(dst, src []byte) {
    var left, right, temp uint32

    var n int32

    /* Start by getting the data into two 32-bit words (endian corect) */

    left  = bytesToUint32(src[0:])
    right = bytesToUint32(src[4:])

    n = 7

    for n >= 0 {
        temp = this.FO(right, n)
        temp = this.FL(temp, n)
        n--

        left ^= temp

        temp = this.FL(left, n)
        temp = this.FO(temp, n)
        n--

        right ^= temp
    }

    leftBytes := uint32ToBytes(left)
    rightBytes := uint32ToBytes(right)

    copy(dst[0:], leftBytes)
    copy(dst[4:], rightBytes)
}

func (this *kasumiCipher) FI(in uint16, subkey uint16) uint16 {
    var nine, seven uint16

    /* The sixteen bit input is split into two unequal halves,  *
     * nine bits and seven bits - as is the subkey			  */

    nine  = in >> 7
    seven = in & 0x7F

    /* Now run the various operations */

    nine  = S9[nine]  ^ seven
    seven = S7[seven] ^ (nine & 0x7F)

    seven ^= subkey >> 9
    nine  ^= subkey & 0x1FF

    nine  = S9[nine]  ^ seven
    seven = S7[seven] ^ (nine & 0x7F)

    in = (seven << 9) + nine

    return in
}

func (this *kasumiCipher) FO(in uint32, index int32) uint32 {
    var left, right uint16

    left  = uint16(in >> 16)
    right = uint16(in)

    left ^= this.KOi1[index]
    left  = this.FI(left, this.KIi1[index])
    left ^= right

    right ^= this.KOi2[index]
    right  = this.FI(right, this.KIi2[index])
    right ^= left

    left ^= this.KOi3[index]
    left  = this.FI(left, this.KIi3[index])
    left ^= right

    in = (uint32(right) << 16) | uint32(left)

    return in
}

func (this *kasumiCipher) FL(in uint32, index int32) uint32 {
    var l, r, a, b uint16

    l = uint16(in >> 16)
    r = uint16(in)

    a  = uint16(l & this.KLi1[index])
    r ^= ROL16(a, 1)

    b  = uint16(r | this.KLi2[index])
    l ^= ROL16(b, 1)

    in = uint32(l) << 16 | uint32(r)

    return in
}

func (this *kasumiCipher) KeySchedule(k []byte) {
    var key, Kprime [8]uint16
    var n int32

    for n = 0; n < 8; n++ {
        key[n] = uint16(k[n * 2]) << 8 | uint16(k[(n * 2) + 1])
    }

    for n = 0; n < 8; n++ {
        Kprime[n] = uint16(key[n] ^ C[n])
    }

    for n = 0; n < 8; n++ {
        this.KLi1[n] = ROL16(key[n], 1)
        this.KLi2[n] = Kprime[(n + 2) & 0x7]
        this.KOi1[n] = ROL16(key[(n + 1) & 0x7], 5)
        this.KOi2[n] = ROL16(key[(n + 5) & 0x7], 8)
        this.KOi3[n] = ROL16(key[(n + 6) & 0x7], 13)
        this.KIi1[n] = Kprime[(n + 4) & 0x7]
        this.KIi2[n] = Kprime[(n + 3) & 0x7]
        this.KIi3[n] = Kprime[(n + 7) & 0x7]
    }
}
