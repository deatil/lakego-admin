package loki97

import (
    "unsafe"
    "strconv"
    "crypto/cipher"
)

const (
    BlockSize = 16
)

var (
    S1 [S1_SIZE]byte
    S2 [S2_SIZE]byte

    P [PERMUTATION_SIZE]ULONG64
)

func init() {
    S1 = generationS1Box()
    S2 = generationS2Box()

    P = permutationGeneration()
}

type loki97Cipher struct {
    key []ULONG64
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    newKey := makeKey(key)

    c := new(loki97Cipher)
    c.key = newKey[:]

    return c, nil
}

func (this *loki97Cipher) BlockSize() int {
    return BlockSize
}

func (this *loki97Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("crypto/loki97: input not full block")
    }

    if len(dst) < BlockSize {
        panic("crypto/loki97: output not full block")
    }

    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("crypto/loki97: invalid buffer overlap")
    }

    encBlock := blockEncrypt(src, this.key)
    copy(dst, encBlock)
}

func (this *loki97Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("crypto/loki97: input not full block")
    }

    if len(dst) < BlockSize {
        panic("crypto/loki97: output not full block")
    }

    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("crypto/loki97: invalid buffer overlap")
    }

    decBlock := blockDecrypt(src, this.key);
    copy(dst, decBlock)
}

// anyOverlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
func anyOverlap(x, y []byte) bool {
    return len(x) > 0 && len(y) > 0 &&
        uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
        uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// inexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// inexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func inexactOverlap(x, y []byte) bool {
    if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
        return false
    }

    return anyOverlap(x, y)
}

type KeySizeError int

func (k KeySizeError) Error() string {
    return "crypto/loki97: invalid key size " + strconv.Itoa(int(k))
}
