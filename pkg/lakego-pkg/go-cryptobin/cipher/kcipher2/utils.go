package kcipher2

/**
 * Do multiplication in GF(2#8) of the irreducible polynomial,
 * f(x) = x#8 + x#4 + x#3 + x + 1. The given parameter is multiplied
 * by 2.
 * @param    t : (INPUT). 8 bits. The number will be multiplied by 2
 * @return     : (OUTPUT). 8 bits. The multiplication result
 */
func gfMultBy2(t uint8) uint8 {
    lq := uint32(t) << 1
    if (lq & 0x100) != 0 {
        lq ^= 0x011B
    }
    q := uint8(lq) ^ 0xFF

    return q
}

/**
 * Do multiplication in GF(2#8) of the irreducible polynomial,
 * f(x) = x#8 + x#4 + x#3 + x + 1. The given parameter is multiplied
 * by 3.
 * @param    t   : (INPUT). 8 bits. The number will be multiplied by 3
 * @return       : (OUTPUT). 8 bits. The multiplication result
 */
func gfMultBy3(t uint8) uint8 {
    lq := (uint32(t) << 1) ^ uint32(t)
    if (lq & 0x100) != 0 {
        lq ^= 0x011B
    }
    q := uint8(lq) ^ 0xFF

    return q
}

/**
 * Do substitution on a given input.
 * @param    t   : (INPUT), (1*32) bits
 * @return       : (OUTPUT), (1*32) bits
 */
func subK2(in uint32) uint32 {
    w0 := uint8(in)
    w1 := uint8(in >> 8)
    w2 := uint8(in >> 16)
    w3 := uint8(in >> 24)

    t0 := sBox[w0]
    t1 := sBox[w1]
    t2 := sBox[w2]
    t3 := sBox[w3]

    q0 := gfMultBy2(t0) ^ gfMultBy3(t1) ^ t2 ^ t3
    q1 := t0 ^ gfMultBy2(t1) ^ gfMultBy3(t2) ^ t3
    q2 := t0 ^ t1 ^ gfMultBy2(t2) ^ gfMultBy3(t3)
    q3 := gfMultBy3(t0) ^ t1 ^ t2 ^ gfMultBy2(t3)

    out := uint32(q3)<<24 | uint32(q2)<<16 | uint32(q1)<<8 | uint32(q0)

    return out
}

/**
 * Non-linear function. See Section 2.4.1.
 * @param    A   : (INPUT), 8 bits
 * @param    B   : (INPUT), 8 bits
 * @param    C   : (INPUT), 8 bits
 * @param    D   : (INPUT), 8 bits
 * @return       : (OUTPUT), 8 bits
 */
func nlf(a, b, c, d uint32) uint32 {
    q := (a + b) ^ c ^ d
    return q
}

