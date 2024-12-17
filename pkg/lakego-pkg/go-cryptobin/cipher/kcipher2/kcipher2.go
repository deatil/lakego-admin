// Package kcipher2 implements the KCipher-2 stream cipher
package kcipher2

import (
    "strconv"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/*

This package is a direct translation of the C code from the RFC.

http://tools.ietf.org/html/rfc7008
http://www.cryptrec.go.jp/english/cryptrec_13_spec_cypherlist_files/PDF/21_00espec.pdf

*/

type mode int

const (
    modeInit   = 0
    modeNormal = 1
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/kcipher2: invalid key size " + strconv.Itoa(int(k))
}

type IVSizeError int

func (iv IVSizeError) Error() string {
    return "go-cryptobin/kcipher2: invalid iv size " + strconv.Itoa(int(iv))
}

type kcipher2Cipher struct {
    a              [5]uint32
    b              [11]uint32
    iv             [4]uint32
    ik             [12]uint32
    l1, r1, l2, r2 uint32

    sbytes [8]byte
    svalid int
}

// NewCipher returns a cipher.Stream implementing the KCipher-2 stream cipher.  The key and iv parameters must each be 16 bytes.
func NewCipher(key []byte, iv []byte) (cipher.Stream, error) {
    if l := len(key); l != 16 {
        return nil, KeySizeError(l)
    }

    if l := len(iv); l != 16 {
        return nil, IVSizeError(l)
    }

    c := &kcipher2Cipher{}
    c.expandKey(key, iv)

    return c, nil
}

func (k *kcipher2Cipher) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/kcipher2: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/kcipher2: invalid buffer overlap")
    }

    for i := range src {
        if k.svalid == 0 {
            zh, zl := k.stream()
            k.next(modeNormal)
            binary.BigEndian.PutUint32(k.sbytes[:], zh)
            binary.BigEndian.PutUint32(k.sbytes[4:], zl)
            k.svalid = 8
        }

        dst[i] = src[i] ^ k.sbytes[8-k.svalid]
        k.svalid--
    }

    copy(dst, src)
}

/**
 * Expand a given 128-bit key (K) to a 384-bit internal key
 * information (IK).
 * See Step 1 of init() in Section 2.3.2.
 * @param    key[4]  : (INPUT), (4*32) bits
 * @param    iv[4]   : (INPUT), (4*32) bits
 * @modify   IK[12]  : (OUTPUT), (12*32) bits
 * @modify   IV[12]  : (OUTPUT), (4*32) bits
 */
func (k *kcipher2Cipher) keyExpansion(key []uint32, iv []uint32) {
    // copy iv to IV
    k.iv[0] = iv[0]
    k.iv[1] = iv[1]
    k.iv[2] = iv[2]
    k.iv[3] = iv[3]

    // m = 0 ... 3
    k.ik[0] = key[0]
    k.ik[1] = key[1]
    k.ik[2] = key[2]
    k.ik[3] = key[3]
    // m = 4
    k.ik[4] = k.ik[0] ^ subK2((k.ik[3]<<8)^(k.ik[3]>>24)) ^ 0x01000000

    // m = 4 ... 11, but not 4 nor 8
    k.ik[5] = k.ik[1] ^ k.ik[4]
    k.ik[6] = k.ik[2] ^ k.ik[5]
    k.ik[7] = k.ik[3] ^ k.ik[6]

    // m = 8
    k.ik[8] = k.ik[4] ^ subK2((k.ik[7]<<8)^(k.ik[7]>>24)) ^ 0x02000000

    // m = 4 ... 11, but not 4 nor 8
    k.ik[9] = k.ik[5] ^ k.ik[8]
    k.ik[10] = k.ik[6] ^ k.ik[9]
    k.ik[11] = k.ik[7] ^ k.ik[10]
}

/**
 * Set up the initial state value using IK and IV. See Step 2 of
 * init() in Section 2.3.2.
 * @param    key[4]  : (INPUT), (4*32) bits
 * @param    iv[4]   : (INPUT), (4*32) bits
 * @modify   S       : (OUTPUT), (A, B, L1, R1, L2, R2)
 */
func (k *kcipher2Cipher) setupStatueValues(key []uint32, iv []uint32) {
    // setting up IK and IV by calling key_expansion(key, iv)
    k.keyExpansion(key, iv)

    // setting up the internal state values
    k.a[0] = k.ik[4]
    k.a[1] = k.ik[3]
    k.a[2] = k.ik[2]
    k.a[3] = k.ik[1]
    k.a[4] = k.ik[0]

    k.b[0] = k.ik[10]
    k.b[1] = k.ik[11]
    k.b[2] = k.iv[0]
    k.b[3] = k.iv[1]
    k.b[4] = k.ik[8]
    k.b[5] = k.ik[9]
    k.b[6] = k.iv[2]
    k.b[7] = k.iv[3]
    k.b[8] = k.ik[7]
    k.b[9] = k.ik[5]
    k.b[10] = k.ik[6]

    k.l1 = 0
    k.r1 = 0
    k.l2 = 0
    k.r2 = 0
}

/**
 * Initialize the system with a 128-bit key (K) and a 128-bit
 * initialization vector (IV). It sets up the internal state value
 * and invokes next(INIT) iteratively 24 times. After this,
 * the system is ready to produce key streams. See Section 2.3.2.
 * @param    key[16] : (INPUT), 16 bytes
 * @param    iv[16]  : (INPUT), 16 bytes
 * @modify   IK      : (12*32) bits, by calling setup_state_values()
 * @modify   IV      : (4*32) bits,  by calling setup_state_values()
 * @modify   S       : (OUTPUT), (A, B, L1, R1, L2, R2)
 */
func (k *kcipher2Cipher) expandKey(key []byte, iv []byte) {
    var k32 [4]uint32
    for i := 0; i < 4; i++ {
        k32[i] = binary.BigEndian.Uint32(key)
        key = key[4:]
    }

    var iv32 [4]uint32
    for i := 0; i < 4; i++ {
        iv32[i] = binary.BigEndian.Uint32(iv)
        iv = iv[4:]
    }

    k.setupStatueValues(k32[:], iv32[:])

    for i := 0; i < 24; i++ {
        k.next(modeInit)
    }
}

/**
 * Derive a new state from the current state values.
 * See Section 2.3.1.
 * @param    mode    : (INPUT) INIT (= 0) or NORMAL (= 1)
 * @modify   S       : (OUTPUT)
 */
func (k *kcipher2Cipher) next(m mode) {
    var nA [5]uint32
    var nB [11]uint32

    var temp1, temp2 uint32

    nL1 := subK2(k.r2 + k.b[4])
    nR1 := subK2(k.l2 + k.b[9])
    nL2 := subK2(k.l1)
    nR2 := subK2(k.r1)

    // m = 0 ... 3
    nA[0] = k.a[1]
    nA[1] = k.a[2]
    nA[2] = k.a[3]
    nA[3] = k.a[4]

    // m = 0 ... 9
    nB[0] = k.b[1]
    nB[1] = k.b[2]
    nB[2] = k.b[3]
    nB[3] = k.b[4]
    nB[4] = k.b[5]
    nB[5] = k.b[6]
    nB[6] = k.b[7]
    nB[7] = k.b[8]
    nB[8] = k.b[9]
    nB[9] = k.b[10]

    // update nA[4]
    temp1 = (k.a[0] << 8) ^ amul0[(k.a[0]>>24)]
    nA[4] = temp1 ^ k.a[3]
    if m == modeInit {
        nA[4] ^= nlf(k.b[0], k.r2, k.r1, k.a[4])
    }

    // update nB[10]
    if k.a[2]&0x40000000 != 0 /* if A[2][30] == 1 */ {
        temp1 = (k.b[0] << 8) ^ amul1[(k.b[0]>>24)]
    } else /*if A[2][30] == 0*/ {
        temp1 = (k.b[0] << 8) ^ amul2[(k.b[0]>>24)]
    }

    if k.a[2]&0x80000000 != 0 /* if A[2][31] == 1 */ {
        temp2 = (k.b[8] << 8) ^ amul3[(k.b[8]>>24)]
    } else /* if A[2][31] == 0 */ {
        temp2 = k.b[8]
    }

    nB[10] = temp1 ^ k.b[1] ^ k.b[6] ^ temp2

    if m == modeInit {
        nB[10] ^= nlf(k.b[10], k.l2, k.l1, k.a[0])
    }

    /* copy S' to S */
    k.a[0] = nA[0]
    k.a[1] = nA[1]
    k.a[2] = nA[2]
    k.a[3] = nA[3]
    k.a[4] = nA[4]

    k.b[0] = nB[0]
    k.b[1] = nB[1]
    k.b[2] = nB[2]
    k.b[3] = nB[3]
    k.b[4] = nB[4]
    k.b[5] = nB[5]
    k.b[6] = nB[6]
    k.b[7] = nB[7]
    k.b[8] = nB[8]
    k.b[9] = nB[9]
    k.b[10] = nB[10]

    k.l1 = nL1
    k.r1 = nR1
    k.l2 = nL2
    k.r2 = nR2
}

/**
 * Obtain a key stream = (ZH, ZL) from the current state values.
 * See Section 2.3.3.
 * @param    ZH  : (OUTPUT) (1 * 32)-bit
 * @modify   ZL  : (OUTPUT) (1 * 32)-bit
 */
func (k *kcipher2Cipher) stream() (uint32, uint32) {
    zh := nlf(k.b[10], k.l2, k.l1, k.a[0])
    zl := nlf(k.b[0], k.r2, k.r1, k.a[4])
    return zh, zl
}
