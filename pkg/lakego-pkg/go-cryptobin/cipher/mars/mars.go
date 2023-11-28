package mars

import (
    "unsafe"
    "strconv"
    "crypto/cipher"
    "encoding/binary"
)

const BlockSize = 16

type marsCipher struct {
    key [40]uint32
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

    var in_key []uint32
    var one uint32

    keyints := bytesToUint32s(key[:16])
    in_key = append(in_key, keyints[:]...)

    if k > 16 {
        one = binary.BigEndian.Uint32(key[16:])
        in_key = append(in_key, one)

        one = binary.BigEndian.Uint32(key[20:])
        in_key = append(in_key, one)
    }

    if k > 24 {
        one = binary.BigEndian.Uint32(key[24:])
        in_key = append(in_key, one)

        one = binary.BigEndian.Uint32(key[28:])
        in_key = append(in_key, one)
    }

    c := new(marsCipher)
    c.key = set_key(in_key, uint32(k*8))

    return c, nil
}

func (this *marsCipher) BlockSize() int {
    return BlockSize
}

func (this *marsCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("crypto/loki97: input not full block")
    }

    if len(dst) < BlockSize {
        panic("crypto/loki97: output not full block")
    }

    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("crypto/loki97: invalid buffer overlap")
    }

    in_blk := bytesToUint32s(src)

    encBlock := encrypt(in_blk, this.key)

    encBytes := Uint32sToBytes(encBlock)

    copy(dst, encBytes[:])
}

func (this *marsCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("crypto/loki97: input not full block")
    }

    if len(dst) < BlockSize {
        panic("crypto/loki97: output not full block")
    }

    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("crypto/loki97: invalid buffer overlap")
    }

    in_blk := bytesToUint32s(src)

    decBlock := decrypt(in_blk, this.key);

    decBytes := Uint32sToBytes(decBlock)

    copy(dst, decBytes[:])
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
