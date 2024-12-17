package shacal2

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 32

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/shacal2: invalid key size %d", int(k))
}

type shacal2Cipher struct {
   roundKey []uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    if k < 4 || k > 256 {
        return nil, KeySizeError(k)
    }

    c := new(shacal2Cipher)
    c.expandKey(key)

    return c, nil
}

func (this *shacal2Cipher) BlockSize() int {
    return BlockSize
}

func (this *shacal2Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/shacal2: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/shacal2: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/shacal2: invalid buffer overlap")
    }

    this.encrypt(dst, src)
}

func (this *shacal2Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/shacal2: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/shacal2: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/shacal2: invalid buffer overlap")
    }

    this.decrypt(dst, src)
}

func (this *shacal2Cipher) encrypt(out []byte, in []byte) {
    A := getu32(in[0:])
    B := getu32(in[4:])
    C := getu32(in[8:])
    D := getu32(in[12:])
    E := getu32(in[16:])
    F := getu32(in[20:])
    G := getu32(in[24:])
    H := getu32(in[28:])

    for r := 0; r < 64; r += 8 {
        fwd(A, B, C, &D, E, F, G, &H, this.roundKey[r + 0])
        fwd(H, A, B, &C, D, E, F, &G, this.roundKey[r + 1])
        fwd(G, H, A, &B, C, D, E, &F, this.roundKey[r + 2])
        fwd(F, G, H, &A, B, C, D, &E, this.roundKey[r + 3])
        fwd(E, F, G, &H, A, B, C, &D, this.roundKey[r + 4])
        fwd(D, E, F, &G, H, A, B, &C, this.roundKey[r + 5])
        fwd(C, D, E, &F, G, H, A, &B, this.roundKey[r + 6])
        fwd(B, C, D, &E, F, G, H, &A, this.roundKey[r + 7])
    }

    res := uint32sToBytes([]uint32{A, B, C, D, E, F, G, H})
    copy(out, res)
}

func (this *shacal2Cipher) decrypt(out []byte, in []byte) {
    A := getu32(in[0:])
    B := getu32(in[4:])
    C := getu32(in[8:])
    D := getu32(in[12:])
    E := getu32(in[16:])
    F := getu32(in[20:])
    G := getu32(in[24:])
    H := getu32(in[28:])

    for r := 0; r < 64; r += 8 {
        rev(B, C, D, &E, F, G, H, &A, this.roundKey[63 - r])
        rev(C, D, E, &F, G, H, A, &B, this.roundKey[62 - r])
        rev(D, E, F, &G, H, A, B, &C, this.roundKey[61 - r])
        rev(E, F, G, &H, A, B, C, &D, this.roundKey[60 - r])
        rev(F, G, H, &A, B, C, D, &E, this.roundKey[59 - r])
        rev(G, H, A, &B, C, D, E, &F, this.roundKey[58 - r])
        rev(H, A, B, &C, D, E, F, &G, this.roundKey[57 - r])
        rev(A, B, C, &D, E, F, G, &H, this.roundKey[56 - r])
    }

    res := uint32sToBytes([]uint32{A, B, C, D, E, F, G, H})
    copy(out, res)
}

func (this *shacal2Cipher) expandKey(key []byte) {
    this.roundKey = make([]uint32, 64)

    keyUint32s := bytesToUint32s(key)
    copy(this.roundKey, keyUint32s)

    for i := 16; i < 64; i++ {
        sigma0_15 := sigma(this.roundKey[i - 15], 7, 18, 3)
        sigma1_2 := sigma(this.roundKey[i - 2], 17, 19, 10)

        this.roundKey[i] = this.roundKey[i - 16] + sigma0_15 + this.roundKey[i - 7] + sigma1_2
    }

    for i := 0; i < 64; i++ {
        this.roundKey[i] += rc[i]
    }
}
