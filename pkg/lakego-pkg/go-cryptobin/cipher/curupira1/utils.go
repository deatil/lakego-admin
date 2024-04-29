package curupira1

import (
    "crypto/subtle"
)

// XOR the contents of b into a in-place
func xor(a, b []byte) {
    subtle.XORBytes(a, a, b)
}

func initXTimesTable() {
    var u, d int

    for u = 0x00; u <= 0xFF; u++ {
        d = u << 1
        if d >= 0x100 {
             d = d ^ 0x14D
        }

        xTimesTable[u] = byte(d)
    }
}

func initSBoxTable() {
    P := []int{
        0x3, 0xF, 0xE, 0x0, 0x5, 0x4, 0xB, 0xC, 0xD, 0xA, 0x9, 0x6,
        0x7, 0x8, 0x2, 0x1,
    }
    Q := []int{
        0x9, 0xE, 0x5, 0x6, 0xA, 0x2, 0x3, 0xC, 0xF, 0x0, 0x4, 0xD,
        0x7, 0xB, 0x1, 0x8,
    }

    var u, uh1, uh2, ul1, ul2 int

    for u = 0x00; u <= 0xFF; u++ {
        uh1 = P[byte(u >> 4) & 0xF]
        ul1 = Q[byte(u & 0xF)]
        uh2 = Q[byte(uh1 & 0xC) ^ byte(int(ul1 >> 2) & 0x3)]
        ul2 = P[byte(int(uh1 << 2) & 0xC) ^ byte(ul1 & 0x3)]
        uh1 = P[byte(uh2 & 0xC) ^ byte(int(ul2 >> 2) & 0x3)]
        ul1 = Q[byte(int(uh2 << 2) & 0xC) ^ byte(ul2 & 0x3)]

        sBoxTable[u] = byte((uh1 << 4) ^ ul1)
    }
}

func xTimes(u byte) byte {
    return xTimesTable[u & 0xFF]
}

func cTimes(u byte) byte {
    // see page 13, item 5.
    return xTimes(
        xTimes(
            xTimes(
                xTimes(u) ^ u,
            ) ^ u,
        ),
    )
}

func dTimesa(a []byte, j int, b []byte) {
    // see page 13.
    var d int = 3 * j // Column delta
    var v byte = xTimes(byte(a[0 + d] ^ a[1 + d] ^ a[2 + d]))
    var w byte = xTimes(v)

    b[0 + d] = byte(a[0 + d] ^ v)
    b[1 + d] = byte(a[1 + d] ^ w)
    b[2 + d] = byte(a[2 + d] ^ v ^ w)
}

func eTimesa(a []byte, j int, b []byte, e bool) {
    // see page 14.
    var d int = 3 * j // Column delta.
    var v byte = byte(a[0 + d] ^ a[1 + d] ^ a[2 + d])

    if e {
        v = cTimes(v)
    } else {
        v = byte(cTimes(v) ^ v)
    }

    b[0 + d] = byte(a[0 + d] ^ v)
    b[1 + d] = byte(a[1 + d] ^ v)
    b[2 + d] = byte(a[2 + d] ^ v)
}

func sBox(u byte) byte {
    return sBoxTable[u & 0xFF]
}

func applyNonLinearLayer(a []byte) []byte {
    // see page 6.
    b := make([]byte, 12)

    for i := 0; i < 12; i++ {
        b[i] = sBox(a[i])
    }

    return b
}

func applyPermutationLayer(a []byte) []byte {
    // see page 7.
    b := make([]byte, 12)

    for i := 0; i < 3; i++ {
        for j := 0; j < 4; j++ {
            b[i + 3 * j] = a[i + 3 * (i ^ j)]
        }
    }

    return b
}

func applyLinearDiffusionLayer(a []byte) []byte {
    // see page 7.
    b := make([]byte, 12)

    for j := 0; j < 4; j++ {
        dTimesa(a, j, b)
    }

    return b
}

func applyKeyAddition(a, kr []byte) []byte {
    // see page 7.
    b := make([]byte, 12)

    for i := 0; i < 3; i++ {
        for j := 0; j < 4; j++ {
            b[i + 3 * j] = byte(a[i + 3 * j] ^ kr[i + 3 * j])
        }
    }

    return b
}

func performWhiteningRound(a, k0 []byte) []byte {
    // see page 9.
    return applyKeyAddition(a, k0)
}

func performLastRound(a, kR []byte) []byte {
    // see page 9.
    return applyKeyAddition(
        applyPermutationLayer(
            applyNonLinearLayer(a),
        ),
        kR,
    )
}

func performRound(a, kr []byte) []byte {
    // see page 9.
    return applyKeyAddition(
        applyLinearDiffusionLayer(
            applyPermutationLayer(
                applyNonLinearLayer(a),
            ),
        ),
        kr,
    )
}

func performUnkeyedRound(a []byte) []byte {
    return applyLinearDiffusionLayer(
        applyPermutationLayer(
            applyNonLinearLayer(a),
        ),
    )
}

func calculateScheduleConstant(s int, keyBits int) []byte {
    // see page 7
    var t int = keyBits / 48
    var q []byte = make([]byte, 3 * 2 * t)

    if s == 0 {
        return q
    }

    // For i = 0
    for j := 0; j < 2 * t; j++ {
        q[3 * j] = sBox(byte(2 * t * (s - 1) + j))
        // Note: 2t(s-1) + j is at most 144 for 192 bits cipher key.
    }

    // For i > 0
    for i := 1; i < 3; i++ {
        for j := 0; j < 2 * t; j++ {
            q[i + 3 * j] = 0
        }
    }

    return q
}

func applyConstantAddition(Kr []byte, subkeyRank int, keyBits, t int) []byte {
    // see page 8
    var b []byte = make([]byte, 3 * 2 * t)

    // Do constant addition
    var q []byte = calculateScheduleConstant(subkeyRank, keyBits)
    for i := 0; i < 3; i++ {
        for j := 0; j < 2 * t; j++ {
            b[i + 3 * j] = byte(Kr[i + 3 * j] ^ q[i + 3 * j])
        }
    }

    return b
}

func applyCyclicShift(a []byte, t int) []byte {
    // see page 8
    b := make([]byte, 3 * 2 * t)

    for j := 0; j < 2 * t; j++ {
        // For i = 0.
        b[3 * j] = a[3 * j]
        // For i = 1.
        b[1 + 3 * j] = a[1 + 3 * byte((j + 1) % (2 * t))]

        // For i = 2.
        if j > 0 {
            b[2 + 3 * j] = a[2 + 3 * byte((j - 1) % (2 * t))]
            // Note that (0 - 1) % 2t would give -1.
        } else {
            b[2] = a[2 + 3 * byte(2 * t - 1)]
        }
    }

    return b
}

func applyLinearDiffusion(a []byte, t int) []byte {
    // see page 8
    b := make([]byte, 3 * 2 * t)

    for j := 0; j < 2 * t; j++ {
        eTimesa(a, j, b, true)
    }

    return b
}

func calculateNextSubkey(Kr []byte, subkeyRank int, keyBits, t int) []byte {
    // see pages 7, 8 and 9.
    return applyLinearDiffusion(
        applyCyclicShift(
            applyConstantAddition(
                Kr,
                subkeyRank,
                keyBits,
                t,
            ),
            t,
        ),
        t,
    )
}

func selectRoundKey(Kr []byte) []byte {
    // see page 9.
    kr := make([]byte, 12)

    // For i = 0.
    for j := 0; j < 4; j++ {
        kr[3 * j] = sBox(Kr[3 * j])
    }

    // For i > 0.
    for i := 1; i < 3; i++ {
        for j := 0; j < 4; j++ {
            kr[i + 3 * j] = Kr[i + 3 * j]
        }
    }

    return kr
}

