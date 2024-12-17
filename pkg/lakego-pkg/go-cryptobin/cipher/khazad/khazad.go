package khazad

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/khazad: invalid key size %d", int(k))
}

type khazadCipher struct {
    roundKeyEnc [9]uint64
    roundKeyDec [9]uint64
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

    c := new(khazadCipher)
    c.expandKey(key)

    return c, nil
}

func (this *khazadCipher) BlockSize() int {
    return BlockSize
}

func (this *khazadCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/khazad: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/khazad: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/khazad: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyEnc[:]);
}

func (this *khazadCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/khazad: input not full block")
    }

    if len(dst) < BlockSize {
        panic("go-cryptobin/khazad: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/khazad: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyDec[:]);
}

func (this *khazadCipher) expandKey(key []byte) {
   var S [256]CONST64
   var K2, K1 uint64
   var r int32

   /* use 7th table */
   S = T7;

    /*
    * map unsigned char array cipher key to initial key state (mu):
    */
   K2 =
      (uint64(key[ 0]) << 56) ^
      (uint64(key[ 1]) << 48) ^
      (uint64(key[ 2]) << 40) ^
      (uint64(key[ 3]) << 32) ^
      (uint64(key[ 4]) << 24) ^
      (uint64(key[ 5]) << 16) ^
      (uint64(key[ 6]) <<  8) ^
      (uint64(key[ 7])      )
   K1 =
      (uint64(key[ 8]) << 56) ^
      (uint64(key[ 9]) << 48) ^
      (uint64(key[10]) << 40) ^
      (uint64(key[11]) << 32) ^
      (uint64(key[12]) << 24) ^
      (uint64(key[13]) << 16) ^
      (uint64(key[14]) <<  8) ^
      (uint64(key[15])      )

   /*
    * compute the round keys:
    */
   for r = 0; r <= R; r++ {
      /*
       * K[r] = rho(c[r], K1) ^ K2;
       */
      this.roundKeyEnc[r] =
         T0[int32(K1 >> 56)       ] ^
         T1[int32(K1 >> 48) & 0xff] ^
         T2[int32(K1 >> 40) & 0xff] ^
         T3[int32(K1 >> 32) & 0xff] ^
         T4[int32(K1 >> 24) & 0xff] ^
         T5[int32(K1 >> 16) & 0xff] ^
         T6[int32(K1 >>  8) & 0xff] ^
         T7[int32(K1      ) & 0xff] ^
         c[r] ^ K2

      K2 = K1;
      K1 = this.roundKeyEnc[r];
   }

   /*
    * compute the inverse key schedule:
    * K'^0 = K^R, K'^R = K^0, K'^r = theta(K^{R-r})
    */
   this.roundKeyDec[0] = this.roundKeyEnc[R]

   for r = 1; r < R; r++ {
      K1 = this.roundKeyEnc[R - r]

      this.roundKeyDec[r] =
         T0[int32(S[int32(K1 >> 56)       ]) & 0xff] ^
         T1[int32(S[int32(K1 >> 48) & 0xff]) & 0xff] ^
         T2[int32(S[int32(K1 >> 40) & 0xff]) & 0xff] ^
         T3[int32(S[int32(K1 >> 32) & 0xff]) & 0xff] ^
         T4[int32(S[int32(K1 >> 24) & 0xff]) & 0xff] ^
         T5[int32(S[int32(K1 >> 16) & 0xff]) & 0xff] ^
         T6[int32(S[int32(K1 >>  8) & 0xff]) & 0xff] ^
         T7[int32(S[int32(K1      ) & 0xff]) & 0xff]
   }

   this.roundKeyDec[R] = this.roundKeyEnc[0]
}

func (this *khazadCipher) crypt(dst []byte, src []byte, roundKey []uint64) {
   var r int32
   var state uint64

    /*
    * map plaintext block to cipher state (mu)
    * and add initial round key (sigma[K^0]):
    */
   state =
      (uint64(src[0]) << 56) ^
      (uint64(src[1]) << 48) ^
      (uint64(src[2]) << 40) ^
      (uint64(src[3]) << 32) ^
      (uint64(src[4]) << 24) ^
      (uint64(src[5]) << 16) ^
      (uint64(src[6]) <<  8) ^
      (uint64(src[7])      ) ^
      roundKey[0]

    /*
    * R - 1 full rounds:
    */
    for r = 1; r < R; r++ {
      state =
         T0[int32(state >> 56)       ] ^
         T1[int32(state >> 48) & 0xff] ^
         T2[int32(state >> 40) & 0xff] ^
         T3[int32(state >> 32) & 0xff] ^
         T4[int32(state >> 24) & 0xff] ^
         T5[int32(state >> 16) & 0xff] ^
         T6[int32(state >>  8) & 0xff] ^
         T7[int32(state      ) & 0xff] ^
         roundKey[r]
    }

    /*
    * last round:
    */
   state =
      (T0[int32(state >> 56)       ] & CONST64(0xff00000000000000)) ^
      (T1[int32(state >> 48) & 0xff] & CONST64(0x00ff000000000000)) ^
      (T2[int32(state >> 40) & 0xff] & CONST64(0x0000ff0000000000)) ^
      (T3[int32(state >> 32) & 0xff] & CONST64(0x000000ff00000000)) ^
      (T4[int32(state >> 24) & 0xff] & CONST64(0x00000000ff000000)) ^
      (T5[int32(state >> 16) & 0xff] & CONST64(0x0000000000ff0000)) ^
      (T6[int32(state >>  8) & 0xff] & CONST64(0x000000000000ff00)) ^
      (T7[int32(state      ) & 0xff] & CONST64(0x00000000000000ff)) ^
      roundKey[R]

   /*
    * map cipher state to ciphertext block (mu^{-1}):
    */
   dst[0] = byte(state >> 56)
   dst[1] = byte(state >> 48)
   dst[2] = byte(state >> 40)
   dst[3] = byte(state >> 32)
   dst[4] = byte(state >> 24)
   dst[5] = byte(state >> 16)
   dst[6] = byte(state >>  8)
   dst[7] = byte(state      )
}
