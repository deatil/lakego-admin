package loki97

const NUM_SUBKEYS = 48
var DELTA = ULONG64{0x9E3779B9, 0x7F4A7C15}

func makeKey(k []byte) [NUM_SUBKEYS]ULONG64 {
    var sk [NUM_SUBKEYS]ULONG64 // array of subkeys

    var deltan ULONG64 = DELTA  // multiples of delta

    var i int16 = 0             // index into key input
    var k4, k3, k2, k1 ULONG64  // key schedule 128-bit entities
    var f_out ULONG64           // fn f output value for debug
    var t1, t2 ULONG64

    // pack key into 128-bit entities: k4, k3, k2, k1
    k4 = byteToULONG64(k[0:8])
    k3 = byteToULONG64(k[8:16])

    if len(k) == 16 {
        // 128-bit key - call fn f twice to gen 256 bits
        k2 = compute(k3, k4)
        k1 = compute(k4, k3)
    } else {
        // 192 or 256-bit key - pack k2 from key data
        k2 = byteToULONG64(k[16:24])

        if len(k) == 24 {
            // 192-bit key - call fn f once to gen 256 bits
            k1 = compute(k4, k3)
        } else {
            // 256-bit key - pack k1 from key data
            k1 = byteToULONG64(k[24:32])
        }
    }

    // iterate over all LOKI97 rounds to generate the required subkeys
    for i = 0; i < NUM_SUBKEYS; i++ {
        t1 = add64(k1, k3)
        t2 = add64(t1, deltan)

        f_out = compute(t2, k2)

        sk[i].l = k4.l ^ f_out.l // compute next subkey value using fn f
        sk[i].r = k4.r ^ f_out.r

        k4 = k3                  // exchange the other words around
        k3 = k2
        k2 = k1
        k1 = sk[i]

        deltan = add64(deltan, DELTA) // next multiple of delta
    }

    return sk;
}

// func f
func compute(A ULONG64, B ULONG64) ULONG64 {
    var d, e, f ULONG64

    d.l = ((A.l & ^B.r) | (A.r & B.r))
    d.r = ((A.r & ^B.r) | (A.l & B.r))

    // Compute e = P(Sa(d))
    //    mask out each group of 12 bits for E
    //    then compute first S-box column [S1,S2,S1,S2,S2,S1,S2,S1]
    //    permuting output through P (with extra shift to build full P)

    var s uint32

    s = uint32(S1[(d.l >> 24 | d.r << 8) & 0x1FFF])
    e.l = P[s].l >> 7
    e.r = P[s].r >> 7

    s = uint32(S2[(d.l >> 16) & 0x7FF])
    e.l |= P[s].l >> 6
    e.r |= P[s].r >> 6

    s = uint32(S1[(d.l >> 8) & 0x1FFF])
    e.l |= P[s].l >> 5
    e.r |= P[s].r >> 5

    s = uint32(S2[d.l & 0x7FF])
    e.l |= P[s].l >> 4
    e.r |= P[s].r >> 4

    s = uint32(S2[(d.r >> 24 | d.l << 8) & 0x7FF])
    e.l |= P[s].l >> 3
    e.r |= P[s].r >> 3

    s = uint32(S1[(d.r >> 16) & 0x1FFF])
    e.l |= P[s].l >> 2
    e.r |= P[s].r >> 2

    s = uint32(S2[(d.r >> 8) & 0x7FF])
    e.l |= P[s].l >> 1
    e.r |= P[s].r >> 1

    s = uint32(S1[d.r & 0x1FFF])
    e.l |= P[s].l
    e.r |= P[s].r

    // Compute f = Sb(e,B)
    //    where the second S-box column is [S2,S2,S1,S1,S2,S2,S1,S1]
    //    for each S, lower bits come from e, upper from upper half of B

    f.l = uint32(S2[((e.l >> 24) & 0xFF) | ((B.l >> 21) &  0x700)]) << 24 |
          uint32(S2[((e.l >> 16) & 0xFF) | ((B.l >> 18) &  0x700)]) << 16 |
          uint32(S1[((e.l >>  8) & 0xFF) | ((B.l >> 13) & 0x1F00)]) <<  8 |
          uint32(S1[((e.l      ) & 0xFF) | ((B.l >>  8) & 0x1F00)])

    f.r = uint32(S2[((e.r >> 24) & 0xFF) | ((B.l >> 5) &  0x700)]) << 24 |
          uint32(S2[((e.r >> 16) & 0xFF) | ((B.l >> 2) &  0x700)]) << 16 |
          uint32(S1[((e.r >>  8) & 0xFF) | ((B.l << 3) & 0x1F00)]) <<  8 |
          uint32(S1[( e.r        & 0xFF) | ((B.l << 8) & 0x1F00)])

    return f
}
