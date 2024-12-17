package curupira1

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 12

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/curupira1: invalid key size %d", int(k))
}

type BlockCipher interface {
    cipher.Block
    Sct(dst, src []byte)
}

type curupira1Cipher struct {
   keyBits int
   R int
   t int
   encryptionRoundKeys [][]byte
   decryptionRoundKeys [][]byte
}

// NewCipher creates and returns a new BlockCipher.
func NewCipher(key []byte) (BlockCipher, error) {
    l := len(key)
    switch l {
        case 12, 18, 24:
            break
        default:
            return nil, KeySizeError(l)
    }

    c := new(curupira1Cipher)
    c.expandKey(key)

    return c, nil
}

func (this *curupira1Cipher) BlockSize() int {
    return BlockSize
}

func (this *curupira1Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/curupira1: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/curupira1: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/curupira1: invalid buffer overlap")
    }

    this.processBlock(dst, src, this.encryptionRoundKeys)
}

func (this *curupira1Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/curupira1: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/curupira1: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/curupira1: invalid buffer overlap")
    }

    this.processBlock(dst, src, this.decryptionRoundKeys)
}

/**
 * Applies a square-complete transform to exactly one block of ciphertext,
 * by performing 4 unkeyed Curupira rounds.
 */
func (this *curupira1Cipher) Sct(dst, src []byte) {
    tmp := make([]byte, 12)

    tmp = performUnkeyedRound(src)
    for r := 0; r < 3; r++ {
        tmp = performUnkeyedRound(tmp)
    }

    copy(dst, tmp)
}

func (this *curupira1Cipher) processBlock(dst []byte, src []byte, roundKeys [][]byte) {
    // see page 9.
    var tmp []byte

    tmp = performWhiteningRound(src, roundKeys[0])
    for r := 1; r <= this.R - 1; r++ {
        tmp = performRound(tmp, roundKeys[r])
    }

    tmp = performLastRound(tmp, roundKeys[this.R])
    copy(dst, tmp)
}

func (this *curupira1Cipher) expandKey(key []byte) {
    keyBits := len(key) * 8

    // See end of page 9.
    switch keyBits {
        case 96:
            this.R = 10
        case 144:
            this.R = 14
        case 192:
            this.R = 18
    }

    this.keyBits = keyBits
    this.t = keyBits / 48
    this.keyRound(key)
}

func (this *curupira1Cipher) keyRound(key []byte) {
    // see pages 9 and 10.
    this.encryptionRoundKeys = make([][]byte, this.R + 1)
    this.decryptionRoundKeys = make([][]byte, this.R + 1)

    var Kr, kr []byte

    Kr = make([]byte, len(key))
    copy(Kr, key)

    kr = selectRoundKey(Kr)

    this.encryptionRoundKeys[0] = kr
    for r := 1; r <= this.R; r++ {
        Kr = calculateNextSubkey(Kr, r, this.keyBits, this.t)
        kr = selectRoundKey(Kr)

        this.encryptionRoundKeys[r] = kr
        this.decryptionRoundKeys[this.R - r] = applyLinearDiffusionLayer(kr)
    }

    this.decryptionRoundKeys[0] = this.encryptionRoundKeys[this.R]
    this.decryptionRoundKeys[this.R] = this.encryptionRoundKeys[0]
}
