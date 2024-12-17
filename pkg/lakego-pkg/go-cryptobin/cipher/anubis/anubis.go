package anubis

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/anubis: invalid key size %d", int(k))
}

type anubisCipher struct {
   R int32
   roundKeyEnc [][4]uint32
   roundKeyDec [][4]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    keylen := len(key)

    // Valid sizes (in bytes) are 16, 20, 24, 28, 32, 36, and 40.
    if ((keylen & 3) > 0 || (keylen < 16) || (keylen > 40)) {
        return nil, KeySizeError(len(key))
    }

    c := new(anubisCipher)
    c.expandKey(key)

    return c, nil
}

func (this *anubisCipher) BlockSize() int {
    return BlockSize
}

func (this *anubisCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/anubis: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/anubis: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/anubis: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyEnc)
}

func (this *anubisCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/anubis: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/anubis: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/anubis: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyDec)
}

func (this *anubisCipher) crypt(out []byte, in []byte, W [][4]uint32) {
    var i, j, r int32
    var state, inter [4]uint32
    var ss [][]byte

    R := this.R

    pt := bytesToUint32s(in)

    for i = 0; i < 4; i++ {
        state[i] = pt[i] ^ W[0][i]
    }

    for r = 1; r < R; r++ {
        ss = uint32sToByteArray(state[:])

        for j = 0; j < 4; j++ {
            inter[j] = T[0][ss[0][j]] ^
                 T[1][ss[1][j]] ^
                 T[2][ss[2][j]] ^
                 T[3][ss[3][j]] ^
                 W[r][j]
        }

        copy(state[:], inter[:])
    }

    // could also use U[0] here instead of T[n]
    ss = uint32sToByteArray(state[:])
    for j = 0; j < 4; j++ {
        inter[j] =
            (T[0][ss[0][j]] & states[0]) ^
            (T[1][ss[1][j]] & states[1]) ^
            (T[2][ss[2][j]] & states[2]) ^
            (T[3][ss[3][j]] & states[3]) ^
            W[R][j]
    }

    ct := uint32sToBytes(inter[:])
    copy(out, ct)
}

func (this *anubisCipher) expandKey(key []byte) {
    var N, R, i, j, r int32
    var W [][4]uint32
    var t []uint32
    var kk, ww [][]byte

    /*
     * determine the N length parameter:
     * (N.B. it is assumed that the key length is valid!)
     */
    N = int32(len(key)) / 4

    /*
     * determine number of rounds from key size:
     */
    R = 8 + N
    this.R = R

    W = make([][4]uint32, R+1)
    t = make([]uint32, N)

    k := bytesToUint32s(key)

    // encrypt key
    for r = 0; r <= R; r++ {
        kk = uint32sToByteArray(k)

        W[r] = [4]uint32{}
        for i = 0; i < N; i++ {
            for j = 0; j < 4; j++ {
                W[r][j] ^= U[i][kk[i][j]]
            }
        }

        if r != R {
            for i = 0; i < N; i++ {
                t[i] = T[0][kk[(N + i    ) % N][0]] ^
                       T[1][kk[(N + i - 1) % N][1]] ^
                       T[2][kk[(N + i - 2) % N][2]] ^
                       T[3][kk[(N + i - 3) % N][3]]
            }

            k[0] = t[0] ^ RC[r]
            for i = 1; i < N; i++ {
                k[i] = t[i]
            }
        }
    }

    this.roundKeyEnc = make([][4]uint32, len(W))
    copy(this.roundKeyEnc, W)

    // decrypt key
    for i = 0; i < (R + 1) / 2; i++ {
        for j = 0; j < 4; j++ {
            W[i][j], W[R - i][j] = W[R - i][j], W[i][j]
        }
    }

    for r = 1; r < R; r++ {
        ww = uint32sToByteArray(W[r][:])

        for i = 0; i < 4; i++ {
            W[r][i] = T[0][byte(U[0][ww[i][0]])] ^
                      T[1][byte(U[0][ww[i][1]])] ^
                      T[2][byte(U[0][ww[i][2]])] ^
                      T[3][byte(U[0][ww[i][3]])]
        }
    }

    this.roundKeyDec = make([][4]uint32, len(W))
    copy(this.roundKeyDec, W)
}
