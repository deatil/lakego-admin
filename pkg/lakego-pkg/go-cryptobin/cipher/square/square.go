package square

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * The Square block cipher.
 *
 * Algorithm developed by Joan Daemen <daemen.j@protonworld.com> and
 * Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>.  Description available
 * from http://www.esat.kuleuven.ac.be/~cosicart/pdf/VR-9700.PDF
 *
 * This implementation is in the public domain.
 *
 * @author Paulo S.L.M. Barreto <pbarreto@nw.com.br>
 * @author George Barwood <george.barwood@dial.pipex.com>
 * @author Vincent Rijmen <vincent.rijmen@esat.kuleuven.ac.be>
 *
 * Caveat: this code assumes 32-bit words and probably will not work
 * otherwise.
 *
 * To correctly visualize this file, please set tabstop = 4.
 *
 * @version 2.7 (1999.06.29)
 *
 */

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/square: invalid key size %d", int(k))
}

/*
 * This a byte level implementation.
 * a[0] corresponds with the first byte of the plaintext block,
 * a[0xF] with the last one. same for the ciphertext and the key.
 */
type squareCipher struct {
    ekey [R+1][4]uint32
    dkey [R+1][4]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(squareCipher)
    c.expandKey(key)

    return c, nil
}

func (this *squareCipher) BlockSize() int {
    return BlockSize
}

func (this *squareCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/square: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/square: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/square: invalid buffer overlap")
    }

    var a [4]uint32
    aUints := bytesToUint32s(src)
    copy(a[:], aUints)

    squareEncrypt(&a, this.ekey)

    dstBytes := uint32sToBytes(a[:])
    copy(dst, dstBytes)
}

func (this *squareCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/square: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/square: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/square: invalid buffer overlap")
    }

    var a [4]uint32
    aUints := bytesToUint32s(src)
    copy(a[:], aUints)

    squareDecrypt(&a, this.dkey)

    dstBytes := uint32sToBytes(a[:])
    copy(dst, dstBytes)
}

func (this *squareCipher) expandKey(key []byte) {
    k := bytesToUint32s(key)

    var a [4]uint32
    copy(a[:], k)

    squareGenerateRoundKeys(a, &this.ekey, &this.dkey)
}
