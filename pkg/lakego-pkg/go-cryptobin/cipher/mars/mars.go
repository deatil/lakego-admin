package mars

import (
    "strconv"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return "cryptobin/mars: invalid key size " + strconv.Itoa(int(k))
}

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
    c.key = setKey(in_key, uint32(k*8))

    return c, nil
}

func (this *marsCipher) BlockSize() int {
    return BlockSize
}

func (this *marsCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/mars: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/mars: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/mars: invalid buffer overlap")
    }

    in_blk := bytesToUint32s(src)

    encBlock := encrypt(in_blk, this.key)

    encBytes := Uint32sToBytes(encBlock)

    copy(dst, encBytes[:])
}

func (this *marsCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/mars: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/mars: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/mars: invalid buffer overlap")
    }

    in_blk := bytesToUint32s(src)

    decBlock := decrypt(in_blk, this.key);

    decBytes := Uint32sToBytes(decBlock)

    copy(dst, decBytes[:])
}
