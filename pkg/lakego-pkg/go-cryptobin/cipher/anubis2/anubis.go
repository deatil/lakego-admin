package anubis2

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("cryptobin/anubis: invalid key size %d", int(k))
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
        panic("cryptobin/anubis: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/anubis: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/anubis: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyEnc, this.R)
}

func (this *anubisCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/anubis: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/anubis: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/anubis: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyDec, this.R)
}

func (this *anubisCipher) crypt(ciphertext []byte, plaintext []byte, roundKey [19][4]uint32, R int32) {
    var i, r int32
    var state [4]uint32
    var inter [4]uint32

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
        inter[0] =
            T0[byte(state[0] >> 24)] ^
            T1[byte(state[1] >> 24)] ^
            T2[byte(state[2] >> 24)] ^
            T3[byte(state[3] >> 24)] ^
            roundKey[r][0]
        inter[1] =
            T0[byte(state[0] >> 16)] ^
            T1[byte(state[1] >> 16)] ^
            T2[byte(state[2] >> 16)] ^
            T3[byte(state[3] >> 16)] ^
            roundKey[r][1]
        inter[2] =
            T0[byte(state[0] >>  8)] ^
            T1[byte(state[1] >>  8)] ^
            T2[byte(state[2] >>  8)] ^
            T3[byte(state[3] >>  8)] ^
            roundKey[r][2]
        inter[3] =
            T0[byte(state[0]      )] ^
            T1[byte(state[1]      )] ^
            T2[byte(state[2]      )] ^
            T3[byte(state[3]      )] ^
            roundKey[r][3]

        state[0] = inter[0]
        state[1] = inter[1]
        state[2] = inter[2]
        state[3] = inter[3]
    }

    /*
     * last round:
     */
    inter[0] =
        (T0[byte(state[0] >> 24)] & 0xff000000) ^
        (T1[byte(state[1] >> 24)] & 0x00ff0000) ^
        (T2[byte(state[2] >> 24)] & 0x0000ff00) ^
        (T3[byte(state[3] >> 24)] & 0x000000ff) ^
        roundKey[R][0]
    inter[1] =
        (T0[byte(state[0] >> 16)] & 0xff000000) ^
        (T1[byte(state[1] >> 16)] & 0x00ff0000) ^
        (T2[byte(state[2] >> 16)] & 0x0000ff00) ^
        (T3[byte(state[3] >> 16)] & 0x000000ff) ^
        roundKey[R][1]
    inter[2] =
        (T0[byte(state[0] >>  8)] & 0xff000000) ^
        (T1[byte(state[1] >>  8)] & 0x00ff0000) ^
        (T2[byte(state[2] >>  8)] & 0x0000ff00) ^
        (T3[byte(state[3] >>  8)] & 0x000000ff) ^
        roundKey[R][2]
    inter[3] =
        (T0[byte(state[0]      )] & 0xff000000) ^
        (T1[byte(state[1]      )] & 0x00ff0000) ^
        (T2[byte(state[2]      )] & 0x0000ff00) ^
        (T3[byte(state[3]      )] & 0x000000ff) ^
        roundKey[R][3]

    /*
     * map cipher state to ciphertext block (mu^{-1}):
     */
    ct := uint32sToBytes(inter)
    copy(ciphertext, ct[:])
}

func (this *anubisCipher) expandKey(key []byte) {
    var N, R, i, r int32
    var kappa [MAX_N]uint32
    var inter [MAX_N]uint32 /* initialize as all zeroes */
    var v, K0, K1, K2, K3 uint32

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
    keys := keyToUint32s(key)
    for i = 0; i < N; i++ {
        kappa[i] = keys[i]
    }

    /*
     * generate R + 1 round keys:
     */
    for r = 0; r <= R; r++ {
        /*
         * generate r-th round key K^r:
         */
        K0 = T4[byte(kappa[N - 1] >> 24)]
        K1 = T4[byte(kappa[N - 1] >> 16)]
        K2 = T4[byte(kappa[N - 1] >>  8)]
        K3 = T4[byte(kappa[N - 1]      )]

        for i = N - 2; i >= 0; i-- {
            K0 = T4[byte(kappa[i] >> 24)] ^
                (T5[byte(K0 >> 24)] & 0xff000000) ^
                (T5[byte(K0 >> 16)] & 0x00ff0000) ^
                (T5[byte(K0 >>  8)] & 0x0000ff00) ^
                (T5[byte(K0      )] & 0x000000ff)
            K1 = T4[byte(kappa[i] >> 16)] ^
                (T5[byte(K1 >> 24)] & 0xff000000) ^
                (T5[byte(K1 >> 16)] & 0x00ff0000) ^
                (T5[byte(K1 >>  8)] & 0x0000ff00) ^
                (T5[byte(K1      )] & 0x000000ff)
            K2 = T4[byte(kappa[i] >>  8)] ^
                (T5[byte(K2 >> 24)] & 0xff000000) ^
                (T5[byte(K2 >> 16)] & 0x00ff0000) ^
                (T5[byte(K2 >>  8)] & 0x0000ff00) ^
                (T5[byte(K2      )] & 0x000000ff)
            K3 = T4[byte(kappa[i]      )] ^
                (T5[byte(K3 >> 24)] & 0xff000000) ^
                (T5[byte(K3 >> 16)] & 0x00ff0000) ^
                (T5[byte(K3 >>  8)] & 0x0000ff00) ^
                (T5[byte(K3      )] & 0x000000ff)
        }

        this.roundKeyEnc[r][0] = K0
        this.roundKeyEnc[r][1] = K1
        this.roundKeyEnc[r][2] = K2
        this.roundKeyEnc[r][3] = K3

        /*
        * compute kappa^{r+1} from kappa^r:
        */
        if r == R {
            break;
        }

        for i = 0; i < N; i++ {
            var j int32 = i

            inter[i]  = T0[byte(kappa[j] >> 24)]
            j--
            if j < 0 {
                j = N - 1
            }

            inter[i] ^= T1[byte(kappa[j] >> 16)]
            j--
            if j < 0 {
                j = N - 1
            }

            inter[i] ^= T2[byte(kappa[j] >>  8)]
            j--
            if j < 0 {
                j = N - 1
            }

            inter[i] ^= T3[byte(kappa[j  ]      )]
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

            this.roundKeyDec[r][i] =
                T0[byte(T4[byte(v >> 24)])] ^
                T1[byte(T4[byte(v >> 16)])] ^
                T2[byte(T4[byte(v >>  8)])] ^
                T3[byte(T4[byte(v      )])]
        }
    }
}
