// Package twine implements the TWINE lightweight block cipher
package twine

import (
    "strconv"
    "crypto/cipher"
)

/*

http://www.nec.co.jp/rd/media/code/research/images/twine_LC11.pdf
http://jpn.nec.com/rd/crl/code/research/image/twine_SAC_full_v4.pdf
https://eprint.iacr.org/2012/422.pdf

*/

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/twine: invalid key size " + strconv.Itoa(int(k))
}

type twineCipher struct {
    rk [36][8]byte
}

// NewCipher returns a cipher.Block implementing the TWINE block cipher.  The key
// argument should be 10 or 16 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
    l := len(key)
    switch l {
        case 10, 16:
            break
        default:
            return nil, KeySizeError(l)
    }

    tw := &twineCipher{}

    switch l {
        case 10:
            tw.expandKeys80(key)
        case 16:
            tw.expandKeys128(key)
    }

    return tw, nil

}

func (t *twineCipher) BlockSize() int {
    return BlockSize
}

func (t *twineCipher) Encrypt(dst, src []byte) {
    var x [16]byte

    for i := 0; i < len(src); i++ {
        x[2*i] = src[i] >> 4
        x[2*i+1] = src[i] & 0x0f
    }

    for i := 0; i < 35; i++ {
        for j := 0; j < 8; j++ {
            x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
        }

        var xnext [16]byte
        for h := 0; h < 16; h++ {
            xnext[shuf[h]] = x[h]
        }
        x = xnext
    }

    // last round
    i := 35
    for j := 0; j < 8; j++ {
        x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
    }

    for i := 0; i < 8; i++ {
        dst[i] = x[2*i]<<4 | x[2*i+1]
    }
}

func (t *twineCipher) Decrypt(dst, src []byte) {
    var x [16]byte

    for i := 0; i < len(src); i++ {
        x[2*i] = src[i] >> 4
        x[2*i+1] = src[i] & 0x0f
    }

    for i := 35; i >= 1; i-- {
        for j := 0; j < 8; j++ {
            x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
        }

        var xnext [16]byte
        for h := 0; h < 16; h++ {
            xnext[shufinv[h]] = x[h]
        }
        x = xnext
    }

    // last round
    i := 0
    for j := 0; j < 8; j++ {
        x[2*j+1] ^= sbox[x[2*j]^t.rk[i][j]]
    }

    for i := 0; i < 8; i++ {
        dst[i] = x[2*i]<<4 | x[2*i+1]
    }
}

func (t *twineCipher) expandKeys80(key []byte) {
    var wk [20]byte

    for i := 0; i < len(key); i++ {
        wk[2*i] = key[i] >> 4
        wk[2*i+1] = key[i] & 0x0f
    }

    for i := 0; i < 35; i++ {

        t.rk[i][0] = wk[1]
        t.rk[i][1] = wk[3]
        t.rk[i][2] = wk[4]
        t.rk[i][3] = wk[6]
        t.rk[i][4] = wk[13]
        t.rk[i][5] = wk[14]
        t.rk[i][6] = wk[15]
        t.rk[i][7] = wk[16]

        wk[1] ^= sbox[wk[0]]
        wk[4] ^= sbox[wk[16]]
        con := roundconst[i]
        wk[7] ^= con >> 3
        wk[19] ^= con & 7

        tmp0, tmp1, tmp2, tmp3 := wk[0], wk[1], wk[2], wk[3]
        // TODO(dgryski): replace with copy()?
        for j := 0; j < 4; j++ {
            fourj := j * 4
            wk[fourj] = wk[fourj+4]
            wk[fourj+1] = wk[fourj+5]
            wk[fourj+2] = wk[fourj+6]
            wk[fourj+3] = wk[fourj+7]
        }
        wk[16] = tmp1
        wk[17] = tmp2
        wk[18] = tmp3
        wk[19] = tmp0
    }

    t.rk[35][0] = wk[1]
    t.rk[35][1] = wk[3]
    t.rk[35][2] = wk[4]
    t.rk[35][3] = wk[6]
    t.rk[35][4] = wk[13]
    t.rk[35][5] = wk[14]
    t.rk[35][6] = wk[15]
    t.rk[35][7] = wk[16]
}

func (t *twineCipher) expandKeys128(key []byte) {
    var wk [32]byte

    for i := 0; i < len(key); i++ {
        wk[2*i] = key[i] >> 4
        wk[2*i+1] = key[i] & 0x0f
    }

    for i := 0; i < 35; i++ {
        t.rk[i][0] = wk[2]
        t.rk[i][1] = wk[3]
        t.rk[i][2] = wk[12]
        t.rk[i][3] = wk[15]
        t.rk[i][4] = wk[17]
        t.rk[i][5] = wk[18]
        t.rk[i][6] = wk[28]
        t.rk[i][7] = wk[31]

        wk[1] ^= sbox[wk[0]]
        wk[4] ^= sbox[wk[16]]
        wk[23] ^= sbox[wk[30]]
        con := roundconst[i]
        wk[7] ^= con >> 3
        wk[19] ^= con & 7

        tmp0, tmp1, tmp2, tmp3 := wk[0], wk[1], wk[2], wk[3]
        // TODO(dgryski): replace with copy()?
        for j := 0; j < 7; j++ {
            fourj := j * 4
            wk[fourj] = wk[fourj+4]
            wk[fourj+1] = wk[fourj+5]
            wk[fourj+2] = wk[fourj+6]
            wk[fourj+3] = wk[fourj+7]
        }
        wk[28] = tmp1
        wk[29] = tmp2
        wk[30] = tmp3
        wk[31] = tmp0
    }

    t.rk[35][0] = wk[2]
    t.rk[35][1] = wk[3]
    t.rk[35][2] = wk[12]
    t.rk[35][3] = wk[15]
    t.rk[35][4] = wk[17]
    t.rk[35][5] = wk[18]
    t.rk[35][6] = wk[28]
    t.rk[35][7] = wk[31]
}
