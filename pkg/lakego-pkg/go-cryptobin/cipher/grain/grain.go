package grain

import (
    "errors"
    "runtime"
    "strconv"
    "crypto/subtle"
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

var errOpen = errors.New("go-cryptobin/grain: message authentication failed")

// state is the pure Go "generic" implementation of
// Grain-128AEAD.
//
// Grain-128AEAD has two primary parts:
//
//    1. pre-output generator
//    2. authenticator generator
//
// The pre-output generator has three parts:
//
//    1. an LFSR
//    2. a non-linear FSR (NFSR)
//    3. a pre-output function
//
// The authenticator generator has two parts:
//
//    1. a shift register
//    2. an accumulator
//
// The pre-output generator is defined as
//
//    y_t = h(x) + s_93^t + \sum_{j \in A} b_j^t
//
// where
//
//    A = {2, 15, 36, 45, 64, 73, 89}
//
type state struct {
    // key is the 128-bit key.
    key [4]uint32
    // lfsr is a 128-bit linear feedback shift register.
    //
    // The LFSR is defined as the following polynomial over GF(2)
    //
    //    f(x) = 1 + x^32 + x^47 + x^58 + x^90 + x^121 + x^128
    //
    // and updated with
    //
    //    s_127^(t+1) = s_0^t + s_7^t + s_38^t
    //                + s_70^t + s_81^t + s_96^t
    //                = L(S_t)
    lfsr lfsr
    // nfsr is a 128-bit non-linear feedback shift register.
    //
    // nfsr is defined as the following polynomial over GF(2)
    //
    //    g(x) = 1 + x^32 + x^37 + x^72 + x^102 + x^128
    //         + x^44*x^60 + x^61*x^125 + x^63*x^67
    //         + x^69*x^101 + x^80*x^88 + x^110*x^111
    //         + x^115*x^117 + x^46*x^50*x^58
    //         + x^103*x^104*x^106 + x^33*x^35*x^36*x^40
    //
    // and updated with
    //
    //    b_126^(t+1) = s_0^t + b_0^t + b_26^t + b_56^t
    //                + b_91^t + b_96^t + b_3^t*b_67^t
    //                + b_11^t*b_13^t + b_17^t*b_18^t
    //                + b_27^t*b_59^t + b_40^t*b_48^t
    //                + b_61^t*b_65^t + b_68^t*b_84^t
    //                + b_22^t*b_24^t*b_25^t
    //                + b_70^t*b_78^t*b_82^t
    //                + b_88^t*b_92^t*b_93^t*b_95^t
    //                = s_0^t + F(B_t)
    nfsr nfsr
    // acc is the accumulator half of the authentication
    // generator.
    //
    // Specifically, acc is the authentication tag.
    acc uint64
    // reg is the shift register half of the authentication
    // generaetor, containing the most recent 64 odd bits from
    // the pre-output.
    reg uint64
}

// NewCipher creates a 128-bit Grain128-AEAD AEAD.
//
// Grain128-AEAD must not be used to encrypt more than 2^80 bits
// per key, nonce pair, including additional authenticated data.
func NewCipher(key []byte) (cipher.AEAD, error) {
    if len(key) != KeySize {
        return nil, errors.New("go-cryptobin/grain: bad key length")
    }

    var s state
    s.setKey(key)

    return &s, nil
}

func (s *state) NonceSize() int {
    return NonceSize
}

func (s *state) Overhead() int {
    return TagSize
}

func (s *state) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    if len(nonce) != NonceSize {
        panic("go-cryptobin/grain: incorrect nonce length: " + strconv.Itoa(len(nonce)))
    }
    s.init(nonce)

    ret, out := alias.SliceForAppend(dst, len(plaintext)+TagSize)
    if alias.InexactOverlap(out, plaintext) {
        panic("go-cryptobin/grain: invalid buffer overlap")
    }

    s.encrypt(out[:len(out)-TagSize], plaintext, additionalData)

    s.tag(out[len(out)-TagSize:])

    return ret
}

func (s *state) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    if len(nonce) != NonceSize {
        panic("go-cryptobin/grain: incorrect nonce length: " + strconv.Itoa(len(nonce)))
    }
    if len(ciphertext) < TagSize {
        return nil, errOpen
    }

    s.init(nonce)

    tag := ciphertext[len(ciphertext)-TagSize:]
    ciphertext = ciphertext[:len(ciphertext)-TagSize]

    ret, out := alias.SliceForAppend(dst, len(ciphertext))
    if alias.InexactOverlap(out, ciphertext) {
        panic("go-cryptobin/grain: invalid buffer overlap")
    }

    s.decrypt(out, ciphertext, additionalData)

    expectedTag := make([]byte, TagSize)
    s.tag(expectedTag)

    if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
        for i := range out {
            out[i] = 0
        }
        runtime.KeepAlive(out)
        return nil, errOpen
    }

    return ret, nil
}

func (s *state) encrypt(dst, src, ad []byte) {
    // der contains the DER-encoded length of ad. Always ensure
    // that DER has an even number of bytes to simplify the
    // following loops.
    var der []byte
    if len(ad) <= shortInt {
        // Use DER's "short" encoding.
        if len(ad) > 0 {
            der = []byte{byte(len(ad)), ad[0]}
            ad = ad[1:]
        } else {
            ad = []byte{byte(len(ad))}
        }
    } else {
        d := encode(len(ad))
        n := d.len()
        if n%2 != 0 {
            d[n] = ad[0]
            ad = ad[1:]
            n++
        }
        der = d[:n]
    }

    for len(der) > 0 {
        v := binary.LittleEndian.Uint16(der)
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next(s)), v)
        der = der[2:]
    }

    for len(ad) >= 2 {
        v := binary.LittleEndian.Uint16(ad)
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next(s)), v)
        ad = ad[2:]
    }

    if len(ad) > 0 {
        word := next(s)
        s.accumulate8(uint8(getmb(word)), ad[0])
        if len(src) > 0 {
            dst[0] = uint8(getkb(word)>>8) ^ src[0]
            s.accumulate8(uint8(getmb(word)>>8), src[0])
            src = src[1:]
            dst = dst[1:]
        }
    }

    for len(src) >= 2 {
        next := next(s)
        v := binary.LittleEndian.Uint16(src)
        binary.LittleEndian.PutUint16(dst, getkb(next)^v)
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next), v)
        src = src[2:]
        dst = dst[2:]
    }

    if len(src) > 0 {
        word := next(s)
        dst[0] = byte(getkb(word)) ^ src[0]
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(word),
            0x100|uint16(src[0]))
    } else {
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next(s)), 0x01)
    }
}

func (s *state) decrypt(dst, src, ad []byte) {
    // der contains the DER-encoded length of ad. Always ensure
    // that DER has an even number of bytes to simplify the
    // following loops.
    var der []byte
    if len(ad) <= shortInt {
        if len(ad) > 0 {
            der = []byte{byte(len(ad)), ad[0]}
            ad = ad[1:]
        } else {
            ad = []byte{byte(len(ad))}
        }
    } else {
        d := encode(len(ad))
        n := d.len()
        if n%2 != 0 {
            d[n] = ad[0]
            ad = ad[1:]
            n++
        }
        der = d[:n]
    }

    for len(der) > 0 {
        v := binary.LittleEndian.Uint16(der)
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next(s)), v)
        der = der[2:]
    }

    for len(ad) >= 2 {
        v := binary.LittleEndian.Uint16(ad)
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next(s)), v)
        ad = ad[2:]
    }

    if len(ad) > 0 {
        word := next(s)
        s.accumulate8(uint8(getmb(word)), ad[0])
        if len(src) > 0 {
            dst[0] = uint8(getkb(word)>>8) ^ src[0]
            s.accumulate8(uint8(getmb(word)>>8), dst[0])
            src = src[1:]
            dst = dst[1:]
        }
    }

    for len(src) >= 2 {
        next := next(s)
        v := getkb(next) ^ binary.LittleEndian.Uint16(src)
        binary.LittleEndian.PutUint16(dst, v)
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next), v)
        src = src[2:]
        dst = dst[2:]
    }

    if len(src) > 0 {
        word := next(s)
        dst[0] = byte(getkb(word)) ^ src[0]
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(word),
            0x100|uint16(dst[0]))
    } else {
        s.reg, s.acc = accumulate(s.reg, s.acc, getmb(next(s)), 0x01)
    }
}

func (s *state) tag(dst []byte) {
    binary.LittleEndian.PutUint64(dst, s.acc)
}

func (s *state) setKey(key []byte) {
    _ = key[15] // bounds check hint to compiler
    s.key[0] = binary.LittleEndian.Uint32(key[0:])
    s.key[1] = binary.LittleEndian.Uint32(key[4:])
    s.key[2] = binary.LittleEndian.Uint32(key[8:])
    s.key[3] = binary.LittleEndian.Uint32(key[12:])
}

func (s *state) init(nonce []byte) {
    for _, k := range s.key {
        s.nfsr = s.nfsr.shift(k)
    }

    for i := 0; i < 12; i += 4 {
        s.lfsr = s.lfsr.shift(binary.LittleEndian.Uint32(nonce[i : i+4]))
    }
    s.lfsr = s.lfsr.shift(1<<31 - 1)

    for i := 0; i < 8; i++ {
        ks := next(s)
        s.lfsr = s.lfsr.xor(ks)
        s.nfsr = s.nfsr.xor(ks)
    }

    s.acc = 0
    for i := 0; i < 2; i++ {
        ks := next(s)
        s.acc |= uint64(ks) << (32 * i)
        s.lfsr = s.lfsr.xor(s.key[i])
    }

    s.reg = 0
    for i := 0; i < 2; i++ {
        ks := next(s)
        s.reg |= uint64(ks) << (32 * i)
        s.lfsr = s.lfsr.xor(s.key[i+2])
    }
}

func nextGeneric(s *state) uint32 {
    ln0, ln1, ln2, ln3 := s.lfsr.words()

    v := ln0 ^ ln3
    v ^= (ln1 ^ ln2) >> 6
    v ^= ln0 >> 7
    v ^= ln2 >> 17
    s.lfsr = s.lfsr.shift(uint32(v))

    nn0, nn1, nn2, nn3 := s.nfsr.words()

    u := ln0                                                   // s_0
    u ^= nn0                                                   // b_0
    u ^= nn0 >> 26                                             // b_26
    u ^= nn3                                                   // b_93
    u ^= nn1 >> 24                                             // b_56
    u ^= ((nn0 & nn1) ^ nn2) >> 27                             // b_91 + b_27*b_59
    u ^= (nn0 & nn2) >> 3                                      // b_3*b_67
    u ^= (nn0 >> 11) & (nn0 >> 13)                             // b_11*b_13
    u ^= (nn0 >> 17) & (nn0 >> 18)                             // b_17*b_18
    u ^= (nn1 >> 8) & (nn1 >> 16)                              // b_40*b_48
    u ^= (nn1 >> 29) & (nn2 >> 1)                              // b_61*b_65
    u ^= (nn2 >> 4) & (nn2 >> 20)                              // b_68*b_84
    u ^= (nn2 >> 24) & (nn2 >> 28) & (nn2 >> 29) & (nn2 >> 31) // b_88*b_92*b_93*b_95
    u ^= (nn0 >> 22) & (nn0 >> 24) & (nn0 >> 25)               // b_22*b_24*b_25
    u ^= (nn2 >> 6) & (nn2 >> 14) & (nn2 >> 18)                // b_70*b_78*b_82
    s.nfsr = s.nfsr.shift(uint32(u))

    x := nn0 >> 2
    x ^= nn0 >> 15
    x ^= nn1 >> 4
    x ^= nn1 >> 13
    x ^= nn2
    x ^= nn2 >> 9
    x ^= nn2 >> 25
    x ^= ln2 >> 29
    x ^= (nn0 >> 12) & (ln0 >> 8)
    x ^= (ln0 >> 13) & (ln0 >> 20)
    x ^= (nn2 >> 31) & (ln1 >> 10)
    x ^= (ln1 >> 28) & (ln2 >> 15)
    x ^= (nn0 >> 12) & (nn2 >> 31) & (ln2 >> 30)
    return uint32(x)
}

func accumulateGeneric(reg, acc uint64, ms, pt uint16) (reg1, acc1 uint64) {
    // accumulateGeneric has this signature because it allows the
    // function to be inlined.
    var acctmp uint64
    regtmp := uint32(ms) << 16
    for i := 0; i < 16; i++ {
        acc ^= reg & -uint64(pt&1)
        reg >>= 1

        acctmp ^= uint64(regtmp) & -uint64(pt&1)
        regtmp >>= 1

        pt >>= 1
    }
    return reg | uint64(ms)<<48, acc ^ acctmp<<48
}

func (s *state) accumulate8(ms, pt uint8) {
    var acctmp uint8
    regtmp := uint16(ms) << 8
    reg := s.reg
    acc := s.acc

    for i := 0; i < 8; i++ {
        mask := -uint64(pt & 1)
        acc ^= reg & mask
        reg >>= 1

        acctmp ^= uint8(regtmp) & uint8(mask)
        regtmp >>= 1

        pt >>= 1
    }

    s.reg = reg | uint64(ms)<<56
    s.acc = acc ^ uint64(acctmp)<<56
}
