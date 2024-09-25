package ascon

// Ascon round function/permutation
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf

type state [5]uint64

func (s *state) expandKey(key []byte, blockSize, A, B uint8, nonce []byte) {
    if len(key) != KeySize {
        panic("ascon: invalid key length")
    }

    s[0] = uint64(byte(len(key)*8))<<56 + uint64(blockSize)<<48 + uint64(A)<<40 + uint64(A-B)<<32
    s[1] = getu64(key[0:])
    s[2] = getu64(key[8:])
    s[3] = getu64(nonce[0:])
    s[4] = getu64(nonce[8:])

    s.rounds(uint(A))
}

func (s *state) mixAdditionalData(additionalData []byte, B uint) {
    ad := additionalData
    if len(ad) <= 0 {
        // If there is no additional data, nothing is added
        // and no padding is applied
        return
    }

    for len(ad) >= 8 {
        s[0] ^= getu64(ad)
        ad = ad[8:]
        s.rounds(B)
    }

    // last chunk
    if len(ad) > 0 {
        var buf [8]byte
        n := copy(buf[:], ad)
        // Pad
        buf[n] |= 0x80
        s[0] ^= getu64(buf[:])
        s.rounds(B)
    } else {
        // Pad
        s[0] ^= 0x80 << 56
        s.rounds(B)
    }
}

func (s *state) encrypt(plaintext, dst []byte, B uint) []byte {
    p := plaintext
    c := dst

    for len(p) >= 8 {
        s[0] ^= getu64(p)
        putu64(c, s[0])
        p = p[8:]
        c = c[8:]
        s.rounds(B)
    }

    if len(p) > 0 {
        var buf [8]byte
        n := copy(buf[:], p)
        // Pad
        buf[n] |= 0x80
        s[0] ^= getu64(buf[:])
        // may write up to 7 too many bytes
        // but it's okay because we have space reserved
        // for the tag
        putu64(c, s[0])
        c = c[n:]
    } else {
        // Pad
        s[0] ^= 0x80 << 56
    }

    return c
}

func (s *state) decrypt(ciphertext, dst []byte, B uint) {
    c := ciphertext
    p := dst

    for len(c) >= 8 {
        x := getu64(c)
        putu64(p, x^s[0])
        s[0] = x
        p = p[8:]
        c = c[8:]
        s.rounds(B)
    }

    if len(c) > 0 {
        for i := range p {
            p[i] = c[i] ^ byte(s[0]>>(56-i*8))
        }

        var x uint64
        for i := range p {
            x |= uint64(p[i]) << (56 - i*8)
        }
        x |= 0x80 << (56 - (len(c) * 8)) // Pad

        s[0] ^= x
    } else {
        // Pad
        s[0] ^= 0x80 << 56
    }
}

func (s *state) rounds(r uint) {
    roundGeneric(s, r)
}

// Section 2.6.1, Table 4 (page 13)
// p12 uses 0..12
// p8 uses 4..12
// p6 uses 6..12
var roundConstant = [12]uint8{
    0x00000000000000f0,
    0x00000000000000e1,
    0x00000000000000d2,
    0x00000000000000c3,
    0x00000000000000b4,
    0x00000000000000a5,
    0x0000000000000096,
    0x0000000000000087,
    0x0000000000000078,
    0x0000000000000069,
    0x000000000000005a,
    0x000000000000004b,
}

func roundGeneric(s *state, numRounds uint) {
    var x0, x1, x2, x3, x4 uint64
    x0 = s[0]
    x1 = s[1]
    x2 = s[2]
    x3 = s[3]
    x4 = s[4]

    for _, r := range roundConstant[12-numRounds:] {
        // Section 2.6.1, Addition of Constants (page 13)
        x2 ^= uint64(r)

        // Section 2.6.2 Substitution layer
        // and Section 7.3, Figure 5 (page 42)
        x0 ^= x4
        x4 ^= x3
        x2 ^= x1

        t0 := x4 ^ (^x0 & x1)
        t1 := x0 ^ (^x1 & x2)
        t2 := x1 ^ (^x2 & x3)
        t3 := x2 ^ (^x3 & x4)
        t4 := x3 ^ (^x4 & x0)

        x0 = t1
        x1 = t2
        x2 = t3
        x3 = t4
        x4 = t0

        x1 ^= x0
        x3 ^= x2
        x0 ^= x4
        x2 = ^x2

        // Section 2.6.3 Linear Diffusion Layer
        x0 = x0 ^ rotl(x0, -19) ^ rotl(x0, -28)
        x1 = x1 ^ rotl(x1, -61) ^ rotl(x1, -39)
        x2 = x2 ^ rotl(x2, -1) ^ rotl(x2, -6)
        x3 = x3 ^ rotl(x3, -10) ^ rotl(x3, -17)
        x4 = x4 ^ rotl(x4, -7) ^ rotl(x4, -41)
    }

    s[0] = x0
    s[1] = x1
    s[2] = x2
    s[3] = x3
    s[4] = x4
}
