package rabbit

import (
    "errors"
    "math/bits"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

var (
    errInvalidKeyLen = errors.New("go-cryptobin/rabbit: key must be 16 byte len, not more not less")
    errInvalidIVLen  = errors.New("go-cryptobin/rabbit: iv must be 8 byte len or nothing (zero) at all")
)

type rabbitCipher struct {
    xbit  [8]uint32
    cbit  [8]uint32
    ks    []byte
    carry uint32
    sbit  [16]byte
}

// NewCipher returns a chpher.Stream interface that implemented an XORKeyStream method
// according to RFC 4503, key must be 16 byte len, iv on the other hand is optional but
// must be either zero len or 8 byte len, error will be returned on wrong key/iv len
func NewCipher(key []byte, iv []byte) (cipher.Stream, error) {
    if len(key) != 16 {
        return nil, errInvalidKeyLen
    }
    if len(iv) != 0 && len(iv) != 8 {
        return nil, errInvalidIVLen
    }

    c := new(rabbitCipher)
    c.expandKey(key, iv)

    return c, nil
}

// XORKeyStream read from src and perform xor on every elemnt of src and
// write result on dst
func (r *rabbitCipher) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }
    if len(dst) < len(src) {
        panic("go-cryptobin/rabbit: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/rabbit: invalid buffer overlap")
    }

    for i := range src {
        if len(r.ks) == 0 {
            r.extract()
        }

        dst[i] = src[i] ^ r.ks[0]
        r.ks = r.ks[1:]
    }
}

func (r *rabbitCipher) expandKey(key, iv []byte) {
    var k [4]uint32
    for i := range k {
        k[i] = getu32(key[i*4:])
    }

    r.setupKey(k[:])

    if len(iv) != 0 {
        var v [4]uint16
        for i := range v {
            v[i] = getu16(iv[i*2:])
        }

        r.setupIV(v[:])
    }
}

func (r *rabbitCipher) setupKey(key []uint32) {
    r.xbit[0] = key[0]
    r.xbit[1] = key[3]<<16 | key[2]>>16
    r.xbit[2] = key[1]
    r.xbit[3] = key[0]<<16 | key[3]>>16
    r.xbit[4] = key[2]
    r.xbit[5] = key[1]<<16 | key[0]>>16
    r.xbit[6] = key[3]
    r.xbit[7] = key[2]<<16 | key[1]>>16
    r.cbit[0] = rol32(key[2], 16)
    r.cbit[1] = key[0]&0xffff0000 | key[1]&0xffff
    r.cbit[2] = rol32(key[3], 16)
    r.cbit[3] = key[1]&0xffff0000 | key[2]&0xffff
    r.cbit[4] = rol32(key[0], 16)
    r.cbit[5] = key[2]&0xffff0000 | key[3]&0xffff
    r.cbit[6] = rol32(key[1], 16)
    r.cbit[7] = key[3]&0xffff0000 | key[0]&0xffff

    for i := 0; i < 4; i++ {
        r.nextState()
    }

    r.cbit[0] ^= r.xbit[4]
    r.cbit[1] ^= r.xbit[5]
    r.cbit[2] ^= r.xbit[6]
    r.cbit[3] ^= r.xbit[7]
    r.cbit[4] ^= r.xbit[0]
    r.cbit[5] ^= r.xbit[1]
    r.cbit[6] ^= r.xbit[2]
    r.cbit[7] ^= r.xbit[3]
}

func (r *rabbitCipher) setupIV(iv []uint16) {
    r.cbit[0] ^= uint32(iv[1])<<16 | uint32(iv[0])
    r.cbit[1] ^= uint32(iv[3])<<16 | uint32(iv[1])
    r.cbit[2] ^= uint32(iv[3])<<16 | uint32(iv[2])
    r.cbit[3] ^= uint32(iv[2])<<16 | uint32(iv[0])
    r.cbit[4] ^= uint32(iv[1])<<16 | uint32(iv[0])
    r.cbit[5] ^= uint32(iv[3])<<16 | uint32(iv[1])
    r.cbit[6] ^= uint32(iv[3])<<16 | uint32(iv[2])
    r.cbit[7] ^= uint32(iv[2])<<16 | uint32(iv[0])

    for i := 0; i < 4; i++ {
        r.nextState()
    }
}

func (r *rabbitCipher) nextState() {
    var GRX [8]uint32
    for i := range r.cbit {
        r.carry, r.cbit[i] = bits.Sub32(aro[i], r.cbit[i], r.carry)
    }

    for i := range GRX {
        GRX[i] = gfunction(r.xbit[i], r.cbit[i])
    }

    r.xbit[0x00] = GRX[0] + rol32(GRX[7], 16) + rol32(GRX[6], 16)
    r.xbit[0x01] = GRX[1] + rol32(GRX[0], 8) + GRX[7]
    r.xbit[0x02] = GRX[2] + rol32(GRX[1], 16) + rol32(GRX[0], 16)
    r.xbit[0x03] = GRX[3] + rol32(GRX[2], 8) + GRX[1]
    r.xbit[0x04] = GRX[4] + rol32(GRX[3], 16) + rol32(GRX[2], 16)
    r.xbit[0x05] = GRX[5] + rol32(GRX[4], 8) + GRX[3]
    r.xbit[0x06] = GRX[6] + rol32(GRX[5], 16) + rol32(GRX[4], 16)
    r.xbit[0x07] = GRX[7] + rol32(GRX[6], 8) + GRX[5]
}

func (r *rabbitCipher) extract() {
    var sw [4]uint32
    r.nextState()

    sw[0] = r.xbit[0] ^ (r.xbit[5]>>16 | r.xbit[3]<<16)
    sw[1] = r.xbit[2] ^ (r.xbit[7]>>16 | r.xbit[5]<<16)
    sw[2] = r.xbit[4] ^ (r.xbit[1]>>16 | r.xbit[7]<<16)
    sw[3] = r.xbit[6] ^ (r.xbit[3]>>16 | r.xbit[1]<<16)

    for i := range sw {
        putu32(r.sbit[i*4:], sw[i])
    }

    r.ks = r.sbit[:]
}
