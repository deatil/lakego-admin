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
        panic("cryptobin/anubis: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/anubis: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/anubis: invalid buffer overlap")
    }

    this.crypt(dst, src, this.roundKeyEnc)
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

    this.crypt(dst, src, this.roundKeyDec)
}

func (this *anubisCipher) crypt(out []byte, in []byte, W [][4]uint32) {
    var R int32
    var r uint32
    var s0, s1, s2, s3 uint32
    var t0, t1, t2, t3 uint32

    R = this.R

    pt := bytesToUint32s(in)

    s0 = pt[0] ^ W[0][0]
    s1 = pt[1] ^ W[0][1]
    s2 = pt[2] ^ W[0][2]
    s3 = pt[3] ^ W[0][3]

    for r = 1; r < uint32(R); r++ {
        t0 = T[0][byte(s0 >> 24)] ^
             T[1][byte(s1 >> 24)] ^
             T[2][byte(s2 >> 24)] ^
             T[3][byte(s3 >> 24)] ^
             W[r][0]
        t1 = T[0][byte(s0 >> 16)] ^
             T[1][byte(s1 >> 16)] ^
             T[2][byte(s2 >> 16)] ^
             T[3][byte(s3 >> 16)] ^
             W[r][1]
        t2 = T[0][byte(s0 >> 8)] ^
             T[1][byte(s1 >> 8)] ^
             T[2][byte(s2 >> 8)] ^
             T[3][byte(s3 >> 8)] ^
             W[r][2]
        t3 = T[0][byte(s0)] ^
             T[1][byte(s1)] ^
             T[2][byte(s2)] ^
             T[3][byte(s3)] ^
             W[r][3]

        s0 = t0
        s1 = t1
        s2 = t2
        s3 = t3
    }

    // could also use U[0] here instead of T[n]
    t0 = (T[0][byte(s0 >> (24 - 0 * 8))] & 0xff000000) ^
         (T[1][byte(s1 >> (24 - 0 * 8))] & 0x00ff0000) ^
         (T[2][byte(s2 >> (24 - 0 * 8))] & 0x0000ff00) ^
         (T[3][byte(s3 >> (24 - 0 * 8))] & 0x000000ff) ^
         W[R][0]
    t1 = (T[0][byte(s0 >> (24 - 1 * 8))] & 0xff000000) ^
         (T[1][byte(s1 >> (24 - 1 * 8))] & 0x00ff0000) ^
         (T[2][byte(s2 >> (24 - 1 * 8))] & 0x0000ff00) ^
         (T[3][byte(s3 >> (24 - 1 * 8))] & 0x000000ff) ^
         W[R][1]
    t2 = (T[0][byte(s0 >> (24 - 2 * 8))] & 0xff000000) ^
         (T[1][byte(s1 >> (24 - 2 * 8))] & 0x00ff0000) ^
         (T[2][byte(s2 >> (24 - 2 * 8))] & 0x0000ff00) ^
         (T[3][byte(s3 >> (24 - 2 * 8))] & 0x000000ff) ^
         W[R][2]
    t3 = (T[0][byte(s0 >> (24 - 3 * 8))] & 0xff000000) ^
         (T[1][byte(s1 >> (24 - 3 * 8))] & 0x00ff0000) ^
         (T[2][byte(s2 >> (24 - 3 * 8))] & 0x0000ff00) ^
         (T[3][byte(s3 >> (24 - 3 * 8))] & 0x000000ff) ^
         W[R][3]

    ct := uint32sToBytes([4]uint32{t0, t1, t2, t3})
    copy(out, ct[:])
}

func (this *anubisCipher) expandKey(key []byte) {
    var N, R, i, r int32
    var W [][4]uint32
    var k []uint32
    var t []uint32

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
    k = make([]uint32, N)
    t = make([]uint32, N)

    keys := keyToUint32s(key)

    for i = 0; i < N; i++ {
        k[i] = keys[i]
    }

    // encrypt key
    for r = 0; r <= R; r++ {
        W[r] = [4]uint32{}
        for i = 0; i < N; i++ {
            W[r][0] ^= U[i][byte(k[i] >> 24)]
            W[r][1] ^= U[i][byte(k[i] >> 16)]
            W[r][2] ^= U[i][byte(k[i] >>  8)]
            W[r][3] ^= U[i][byte(k[i]      )]
        }

        if r != R {
            for i = 0; i < N; i++ {
                t[i] = T[0][byte(k[(N + i    ) % N] >> 24)] ^
                       T[1][byte(k[(N + i - 1) % N] >> 16)] ^
                       T[2][byte(k[(N + i - 2) % N] >>  8)] ^
                       T[3][byte(k[(N + i - 3) % N]      )]
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
        W[i][0], W[R - i][0] = W[R - i][0], W[i][0]
        W[i][1], W[R - i][1] = W[R - i][1], W[i][1]
        W[i][2], W[R - i][2] = W[R - i][2], W[i][2]
        W[i][3], W[R - i][3] = W[R - i][3], W[i][3]
    }

    for r = 1; r < R; r++ {
        for i = 0; i < 4; i++ {
            W[r][i] = T[0][byte(U[0][byte(W[r][i] >> 24)])] ^
                      T[1][byte(U[0][byte(W[r][i] >> 16)])] ^
                      T[2][byte(U[0][byte(W[r][i] >>  8)])] ^
                      T[3][byte(U[0][byte(W[r][i]      )])]
        }
    }

    this.roundKeyDec = make([][4]uint32, len(W))
    copy(this.roundKeyDec, W)
}
