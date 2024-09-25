package ascon

import "crypto/subtle"

// Ascon-PRF and Ascon-MAC are specified in "Ascon PRF, MAC, and Short-Input MAC"
// by Christoph Dobraunig and Maria Eichlseder and Florian Mendel and Martin Schläffer.
// https://eprint.iacr.org/2021/1574

type MAC struct {
    s   state
    buf [256 / 8]byte
    len uint8 // number of bytes in buf
}

func NewMAC(key []byte) *MAC {
    d := new(MAC)
    d.expandKey(key)
    return d
}

func (d *MAC) Size() int {
    return TagSize
}

func (d *MAC) BlockSize() int {
    return len(d.buf)
}

// Clone returns a new copy of d.
func (d *MAC) Clone() *MAC {
    new := *d
    return &new
}

// TODO: Reset? we would have to store the key or the initial state somewhere

func (d *MAC) Write(p []byte) (int, error) {
    d.write(p)
    return len(p), nil
}

func (d *MAC) write(b []byte) {
    const bs = BlockSize * 4

    // try to empty the buffer, if it isn't empty already
    if d.len > 0 && int(d.len)+len(b) >= bs {
        n := copy(d.buf[d.len:bs], b)
        d.len += uint8(n)
        b = b[n:]
        if d.len == bs {
            d.s[0] ^= getu64(d.buf[0:])
            d.s[1] ^= getu64(d.buf[8:])
            d.s[2] ^= getu64(d.buf[16:])
            d.s[3] ^= getu64(d.buf[24:])
            d.round()
            d.len = 0
        }
    }

    // absorb bytes directly, skipping the buffer
    for len(b) >= bs {
        d.s[0] ^= getu64(b[0:])
        d.s[1] ^= getu64(b[8:])
        d.s[2] ^= getu64(b[16:])
        d.s[3] ^= getu64(b[24:])
        d.round()
        b = b[bs:]
    }

    // store any remaining bytes in the buffer
    if len(b) > 0 {
        n := copy(d.buf[d.len:bs], b)
        d.len += uint8(n)
    }
}

func (d *MAC) finish() {
    if int(d.len) >= len(d.buf) {
        panic("ascon: internal error")
    }

    // Pad with a 1 followed by zeroes
    const bs = BlockSize * 4
    if d.len == 0 {
        d.s[0] ^= 0x80 << 56
    } else {
        for i := d.len; i < bs; i++ {
            d.buf[i] = 0
        }
        d.buf[d.len] |= 0x80

        // absorb the last block
        d.s[0] ^= getu64(d.buf[0:])
        d.s[1] ^= getu64(d.buf[8:])
        d.s[2] ^= getu64(d.buf[16:])
        d.s[3] ^= getu64(d.buf[24:])
        d.len = 0
    }

    d.s[4] ^= 0x01
    d.round()
}

func (d0 *MAC) Sum(b []byte) []byte {
    d := *d0
    d.finish()

    // Squeeze
    b = appendu64(b, d.s[0])
    b = appendu64(b, d.s[1])

    return b
}

// Verify reports whether the MAC of the previously written bytes is equal to the provided MAC.
// It does not modify the object state.
func (d0 *MAC) Verify(mac []byte) (ok bool) {
    if len(mac) != TagSize {
        // panic?
        return false
    }

    d := *d0
    d.finish()

    // Get the tag and xor with the expected tag
    t0 := d.s[0] ^ getu64(mac[0:])
    t1 := d.s[1] ^ getu64(mac[8:])

    // Constant-time comparison
    t := uint32(t0>>32) | uint32(t0)
    t |= uint32(t1>>32) | uint32(t1)

    return subtle.ConstantTimeEq(int32(t), 0) != 0
}

func (d *MAC) round() {
    d.s.rounds(12)
}

func (d *MAC) expandKey(key []byte) {
    if len(key) != KeySize {
        panic("ascon: wrong key length")
    }

    const r, t, a = 128, 128, 12

    k := len(key) * 8

    d.s[0] = uint64(uint8(k))<<56 + uint64(r)<<48 + uint64(0x80|a)<<40 + uint64(t)
    d.s[1] = getu64(key[0:])
    d.s[2] = getu64(key[8:])
    d.s[3] = 0
    d.s[4] = 0

    d.len = 0
    d.round()
}
