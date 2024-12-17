package anubis2

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
   roundKeyEnc [19][4]uint32
   roundKeyDec [19][4]uint32
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

func (this *anubisCipher) crypt(ciphertext []byte, plaintext []byte, roundKey [19][4]uint32) {
    var i, j, r int32
    var state, inter [4]uint32
    var ss [][]byte

    R := this.R

    pt := bytesToUint32s(plaintext)

    /*
    * map plaintext block to cipher state (mu)
    * and add initial round key (sigma[K^0]):
    */
    for i = 0; i < 4; i++ {
        state[i] = pt[i] ^ roundKey[0][i]
    }

    /*
     * R - 1 full rounds:
     */
    for r = 1; r < R; r++ {
        for j = 0; j < 4; j++ {
            ss = uint32sToByteArray(state[:])

            inter[j] =
                T0[ss[0][j]] ^
                T1[ss[1][j]] ^
                T2[ss[2][j]] ^
                T3[ss[3][j]] ^
                roundKey[r][j]
        }

        copy(state[:], inter[:])
    }

    /*
     * last round:
     */
    ss = uint32sToByteArray(state[:])
    for j = 0; j < 4; j++ {
        inter[j] =
            (T0[ss[0][j]] & states[0]) ^
            (T1[ss[1][j]] & states[1]) ^
            (T2[ss[2][j]] & states[2]) ^
            (T3[ss[3][j]] & states[3]) ^
            roundKey[R][j]
    }

    /*
     * map cipher state to ciphertext block (mu^{-1}):
     */
    ct := uint32sToBytes(inter[:])
    copy(ciphertext, ct)
}

func (this *anubisCipher) expandKey(key []byte) {
    var N, R, i, j, r int32
    var kappa [MAX_N]uint32
    var inter [MAX_N]uint32 /* initialize as all zeroes */
    var v uint32
    var ks [4]uint32
    var kappas [][]byte
    var kss, vv [4]byte

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

    /*
     * map cipher key to initial key state (mu):
     */
    keys := bytesToUint32s(key)
    for i = 0; i < N; i++ {
        kappa[i] = keys[i]
    }

    /*
     * generate R + 1 round keys:
     */
    for r = 0; r <= R; r++ {
        kappas = uint32sToByteArray(kappa[:])

        /*
         * generate r-th round key K^r:
         */
        for j = 0; j < 4; j++ {
            ks[j] = T4[kappas[N - 1][j]]
        }

        for i = N - 2; i >= 0; i-- {
            for j = 0; j < 4; j++ {
                putu32(kss[:], ks[j])

                ks[j] = T4[kappas[i][j]] ^
                    (T5[kss[0]] & states[0]) ^
                    (T5[kss[1]] & states[1]) ^
                    (T5[kss[2]] & states[2]) ^
                    (T5[kss[3]] & states[3])
            }
        }

        copy(this.roundKeyEnc[r][:], ks[:])

        /*
        * compute kappa^{r+1} from kappa^r:
        */
        if r == R {
            break;
        }

        for i = 0; i < N; i++ {
            var j int32 = i

            inter[i] = T0[kappas[j][0]]
            j--
            if j < 0 {
                j = N - 1
            }

            inter[i] ^= T1[kappas[j][1]]
            j--
            if j < 0 {
                j = N - 1
            }

            inter[i] ^= T2[kappas[j][2]]
            j--
            if j < 0 {
                j = N - 1
            }

            inter[i] ^= T3[kappas[j][3]]
        }

        kappa[0] = inter[0] ^ rc[r]
        for i = 1; i < N; i++ {
            kappa[i] = inter[i]
        }
    }

    /*
     * generate inverse key schedule: K'^0 = K^R, K'^R = K^0, K'^r = theta(K^{R-r}):
     */
    for i = 0; i < 4; i++ {
        this.roundKeyDec[0][i] = this.roundKeyEnc[R][i]
        this.roundKeyDec[R][i] = this.roundKeyEnc[0][i]
    }

    for r = 1; r < R; r++ {
        for i = 0; i < 4; i++ {
            v = this.roundKeyEnc[R - r][i]
            putu32(vv[:], v)

            this.roundKeyDec[r][i] = T0[byte(T4[vv[0]])] ^
                                     T1[byte(T4[vv[1]])] ^
                                     T2[byte(T4[vv[2]])] ^
                                     T3[byte(T4[vv[3]])]
        }
    }
}
