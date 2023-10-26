package curve256k1

import "math/bits"

type scalar struct {
    l0, l1, l2, l3 uint64

    // l4 is workspace, and up to 3bit.
    l4 uint64
}

// Lsh8 sets s = v << 8, and return s.
func (s *scalar) Lsh8(v *scalar) *scalar {
    l0 := v.l0 << 8
    l1 := v.l1<<8 | v.l0>>56
    l2 := v.l2<<8 | v.l1>>56
    l3 := v.l3<<8 | v.l2>>56
    l4 := v.l4<<8 | v.l3>>56

    // carry is l4 * 0x1_45512319_50b75fc4_402da173_2fc9bebf
    var h, l, c, c0 uint64
    l2, c = bits.Add64(l2, l4, 0)
    l3, c = bits.Add64(l3, 0, c)
    c0 += c

    h, l = bits.Mul64(l4, 0x45512319_50b75fc4)
    l1, c = bits.Add64(l1, l, 0)
    l2, c = bits.Add64(l2, h, c)
    l3, c = bits.Add64(l3, 0, c)
    c0 += c

    h, l = bits.Mul64(l4, 0x402da173_2fc9bebf)
    l0, c = bits.Add64(l0, l, 0)
    l1, c = bits.Add64(l1, h, c)
    l2, c = bits.Add64(l2, 0, c)
    l3, c = bits.Add64(l3, 0, c)
    c0 += c

    s.l0 = l0
    s.l1 = l1
    s.l2 = l2
    s.l3 = l3
    s.l4 = c0
    return s
}

func (s *scalar) reduce() *scalar {
    l0 := s.l0
    l1 := s.l1
    l2 := s.l2
    l3 := s.l3
    l4 := s.l4

    // carry is l4 * 0x1_45512319_50b75fc4_402da173_2fc9bebf
    var h, l, c uint64
    l2, c = bits.Add64(l2, l4, 0)
    l3, _ = bits.Add64(l3, 0, c)

    h, l = bits.Mul64(l4, 0x45512319_50b75fc4)
    l1, c = bits.Add64(l1, l, 0)
    l2, c = bits.Add64(l2, h, c)
    l3, _ = bits.Add64(l3, 0, c)

    h, l = bits.Mul64(l4, 0x402da173_2fc9bebf)
    l0, c = bits.Add64(l0, l, 0)
    l1, c = bits.Add64(l1, h, c)
    l2, c = bits.Add64(l2, 0, c)
    l3, _ = bits.Add64(l3, 0, c)

    // If v >= l, then v + 0x1_45512319_50b75fc4_402da173_2fc9bebf >= 2^256,
    // which would overflow 2^256 - 1, generating a carry.
    // That is, c will be 0 if v < l, and 1 otherwise.
    _, c = bits.Add64(l0, 0x402da173_2fc9bebf, 0)
    _, c = bits.Add64(l1, 0x45512319_50b75fc4, c)
    _, c = bits.Add64(l2, 1, c)
    _, c = bits.Add64(l3, 0, c)
    c0 := c

    // NOTE: c0 is 0 or 1, so c0*0x45512319_50b75fc4 doesn't overflow
    l0, c = bits.Add64(l0, c0*0x402da173_2fc9bebf, 0)
    l1, c = bits.Add64(l1, c0*0x45512319_50b75fc4, c)
    l2, c = bits.Add64(l2, c0, c)
    l3, _ = bits.Add64(l3, 0, c)

    s.l0 = l0
    s.l1 = l1
    s.l2 = l2
    s.l3 = l3
    s.l4 = 0
    return s
}

func (s *scalar) Add8(v *scalar, u uint8) *scalar {
    l0, c := bits.Add64(v.l0, uint64(u), 0)
    l1, c := bits.Add64(v.l1, 0, c)
    l2, c := bits.Add64(v.l2, 0, c)
    l3, c := bits.Add64(v.l3, 0, c)
    l4, _ := bits.Add64(v.l4, 0, c)
    s.l0 = l0
    s.l1 = l1
    s.l2 = l2
    s.l3 = l3
    s.l4 = l4
    return s
}

func (s *scalar) bytes(buf *[32]byte) {
    s0 := *s
    s0.reduce()
    buf[31] = byte(s0.l0 >> 0)
    buf[30] = byte(s0.l0 >> 8)
    buf[29] = byte(s0.l0 >> 16)
    buf[28] = byte(s0.l0 >> 24)
    buf[27] = byte(s0.l0 >> 32)
    buf[26] = byte(s0.l0 >> 40)
    buf[25] = byte(s0.l0 >> 48)
    buf[24] = byte(s0.l0 >> 56)

    buf[23] = byte(s0.l1 >> 0)
    buf[22] = byte(s0.l1 >> 8)
    buf[21] = byte(s0.l1 >> 16)
    buf[20] = byte(s0.l1 >> 24)
    buf[19] = byte(s0.l1 >> 32)
    buf[18] = byte(s0.l1 >> 40)
    buf[17] = byte(s0.l1 >> 48)
    buf[16] = byte(s0.l1 >> 56)

    buf[15] = byte(s0.l2 >> 0)
    buf[14] = byte(s0.l2 >> 8)
    buf[13] = byte(s0.l2 >> 16)
    buf[12] = byte(s0.l2 >> 24)
    buf[11] = byte(s0.l2 >> 32)
    buf[10] = byte(s0.l2 >> 40)
    buf[9] = byte(s0.l2 >> 48)
    buf[8] = byte(s0.l2 >> 56)

    buf[7] = byte(s0.l3 >> 0)
    buf[6] = byte(s0.l3 >> 8)
    buf[5] = byte(s0.l3 >> 16)
    buf[4] = byte(s0.l3 >> 24)
    buf[3] = byte(s0.l3 >> 32)
    buf[2] = byte(s0.l3 >> 40)
    buf[1] = byte(s0.l3 >> 48)
    buf[0] = byte(s0.l3 >> 56)
}

// parse k as big-endian integer,
// and returns k mod 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141.
func normalizeScalar(k []byte) [32]byte {
    var s scalar
    for _, b := range k {
        s.Lsh8(&s)
        s.Add8(&s, b)
    }

    var buf [32]byte
    s.bytes(&buf)
    return buf
}
