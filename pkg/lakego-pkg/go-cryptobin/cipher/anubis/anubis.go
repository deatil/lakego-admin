package anubis

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
   keyBits int32
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
    c.expandKey(key, int32(keylen))

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
   var i, pos, r int32
   var state [4]uint32
   var inter [4]uint32

    /*
    * map plaintext block to cipher state (mu)
    * and add initial round key (sigma[K^0]):
    */
    for i, pos = 0, 0; i < 4; i, pos = i + 1, pos + 4 {
      state[i] =
         (uint32(plaintext[pos    ]) << 24) ^
         (uint32(plaintext[pos + 1]) << 16) ^
         (uint32(plaintext[pos + 2]) <<  8) ^
         (uint32(plaintext[pos + 3])      ) ^
         roundKey[0][i]
    }

    /*
     * R - 1 full rounds:
     */
    for r = 1; r < R; r++ {
      inter[0] =
         T0[byte(state[0] >> 24) & 0xff] ^
         T1[byte(state[1] >> 24) & 0xff] ^
         T2[byte(state[2] >> 24) & 0xff] ^
         T3[byte(state[3] >> 24) & 0xff] ^
         roundKey[r][0]
      inter[1] =
         T0[byte(state[0] >> 16) & 0xff] ^
         T1[byte(state[1] >> 16) & 0xff] ^
         T2[byte(state[2] >> 16) & 0xff] ^
         T3[byte(state[3] >> 16) & 0xff] ^
         roundKey[r][1]
      inter[2] =
         T0[byte(state[0] >>  8) & 0xff] ^
         T1[byte(state[1] >>  8) & 0xff] ^
         T2[byte(state[2] >>  8) & 0xff] ^
         T3[byte(state[3] >>  8) & 0xff] ^
         roundKey[r][2]
      inter[3] =
         T0[byte(state[0]      ) & 0xff] ^
         T1[byte(state[1]      ) & 0xff] ^
         T2[byte(state[2]      ) & 0xff] ^
         T3[byte(state[3]      ) & 0xff] ^
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
      (T0[byte(state[0] >> 24) & 0xff] & 0xff000000) ^
      (T1[byte(state[1] >> 24) & 0xff] & 0x00ff0000) ^
      (T2[byte(state[2] >> 24) & 0xff] & 0x0000ff00) ^
      (T3[byte(state[3] >> 24) & 0xff] & 0x000000ff) ^
      roundKey[R][0]
   inter[1] =
      (T0[byte(state[0] >> 16) & 0xff] & 0xff000000) ^
      (T1[byte(state[1] >> 16) & 0xff] & 0x00ff0000) ^
      (T2[byte(state[2] >> 16) & 0xff] & 0x0000ff00) ^
      (T3[byte(state[3] >> 16) & 0xff] & 0x000000ff) ^
      roundKey[R][1]
   inter[2] =
      (T0[byte(state[0] >>  8) & 0xff] & 0xff000000) ^
      (T1[byte(state[1] >>  8) & 0xff] & 0x00ff0000) ^
      (T2[byte(state[2] >>  8) & 0xff] & 0x0000ff00) ^
      (T3[byte(state[3] >>  8) & 0xff] & 0x000000ff) ^
      roundKey[R][2]
   inter[3] =
      (T0[byte(state[0]      ) & 0xff] & 0xff000000) ^
      (T1[byte(state[1]      ) & 0xff] & 0x00ff0000) ^
      (T2[byte(state[2]      ) & 0xff] & 0x0000ff00) ^
      (T3[byte(state[3]      ) & 0xff] & 0x000000ff) ^
      roundKey[R][3]

   /*
    * map cipher state to ciphertext block (mu^{-1}):
    */
    for i, pos = 0, 0; i < 4; i, pos = i + 1, pos + 4 {
        var w uint32 = inter[i]

        ciphertext[pos    ] = byte(w >> 24)
        ciphertext[pos + 1] = byte(w >> 16)
        ciphertext[pos + 2] = byte(w >>  8)
        ciphertext[pos + 3] = byte(w      )
    }
}

func (this *anubisCipher) expandKey(key []byte, keylen int32) {
   var N, R, i, pos, r int32
   var kappa [MAX_N]uint32
   var inter [MAX_N]uint32 /* initialize as all zeroes */
   var v, K0, K1, K2, K3 uint32

   this.keyBits = keylen * 8;

   /*
    * determine the N length parameter:
    * (N.B. it is assumed that the key length is valid!)
    */
   N = this.keyBits >> 5;

   /*
    * determine number of rounds from key size:
    */
   R = 8 + N
   this.R = R

   /*
   * map cipher key to initial key state (mu):
   */
   for i, pos = 0, 0; i < N; i, pos = i + 1, pos + 4 {
      kappa[i] =
         (uint32(key[pos    ]) << 24) ^
         (uint32(key[pos + 1]) << 16) ^
         (uint32(key[pos + 2]) <<  8) ^
         (uint32(key[pos + 3])      )
   }

   /*
    * generate R + 1 round keys:
    */
   for r = 0; r <= R; r++ {
      /*
       * generate r-th round key K^r:
       */
      K0 = T4[byte(kappa[N - 1] >> 24) & 0xff]
      K1 = T4[byte(kappa[N - 1] >> 16) & 0xff]
      K2 = T4[byte(kappa[N - 1] >>  8) & 0xff]
      K3 = T4[byte(kappa[N - 1]      ) & 0xff]

      for i = N - 2; i >= 0; i-- {
         K0 = T4[byte(kappa[i] >> 24)  & 0xff] ^
            (T5[byte(K0 >> 24) & 0xff] & 0xff000000) ^
            (T5[byte(K0 >> 16) & 0xff] & 0x00ff0000) ^
            (T5[byte(K0 >>  8) & 0xff] & 0x0000ff00) ^
            (T5[byte(K0      ) & 0xff] & 0x000000ff)
         K1 = T4[byte(kappa[i] >> 16) & 0xff] ^
            (T5[byte(K1 >> 24) & 0xff] & 0xff000000) ^
            (T5[byte(K1 >> 16) & 0xff] & 0x00ff0000) ^
            (T5[byte(K1 >>  8) & 0xff] & 0x0000ff00) ^
            (T5[byte(K1      ) & 0xff] & 0x000000ff)
         K2 = T4[byte(kappa[i] >>  8) & 0xff] ^
            (T5[byte(K2 >> 24) & 0xff] & 0xff000000) ^
            (T5[byte(K2 >> 16) & 0xff] & 0x00ff0000) ^
            (T5[byte(K2 >>  8) & 0xff] & 0x0000ff00) ^
            (T5[byte(K2      ) & 0xff] & 0x000000ff)
         K3 = T4[byte(kappa[i]      ) & 0xff] ^
            (T5[byte(K3 >> 24) & 0xff] & 0xff000000) ^
            (T5[byte(K3 >> 16) & 0xff] & 0x00ff0000) ^
            (T5[byte(K3 >>  8) & 0xff] & 0x0000ff00) ^
            (T5[byte(K3      ) & 0xff] & 0x000000ff)
      }

      this.roundKeyEnc[r][0] = K0;
      this.roundKeyEnc[r][1] = K1;
      this.roundKeyEnc[r][2] = K2;
      this.roundKeyEnc[r][3] = K3;

      /*
       * compute kappa^{r+1} from kappa^r:
       */
      if r == R {
         break;
      }

      for i = 0; i < N; i++ {
         var j int32 = i

         inter[i]  = T0[byte(kappa[j] >> 24) & 0xff]
         j--
         if j < 0 {
            j = N - 1
         }

         inter[i] ^= T1[byte(kappa[j] >> 16) & 0xff]
         j--
         if j < 0 {
            j = N - 1
         }

         inter[i] ^= T2[byte(kappa[j] >>  8) & 0xff]
         j--
         if j < 0 {
            j = N - 1
         }

         inter[i] ^= T3[byte(kappa[j  ]      ) & 0xff]
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
            T0[byte(T4[byte(v >> 24) & 0xff]) & 0xff] ^
            T1[byte(T4[byte(v >> 16) & 0xff]) & 0xff] ^
            T2[byte(T4[byte(v >>  8) & 0xff]) & 0xff] ^
            T3[byte(T4[byte(v      ) & 0xff]) & 0xff]
      }
   }
}
