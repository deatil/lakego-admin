package safer

import (
    "math/bits"
)

const (
    SAFER_K64_DEFAULT_NOF_ROUNDS   =  6
    SAFER_K128_DEFAULT_NOF_ROUNDS  = 10
    SAFER_SK64_DEFAULT_NOF_ROUNDS  =  8
    SAFER_SK128_DEFAULT_NOF_ROUNDS = 10
    SAFER_MAX_NOF_ROUNDS           = 13
    SAFER_BLOCK_LEN                =  8
)

var SAFER_KEY_LEN = (1 + SAFER_BLOCK_LEN * (1 + 2 * SAFER_MAX_NOF_ROUNDS))

func ROL8(x, n uint8) uint8 {
    return bits.RotateLeft8(x, int(n))
}

func EXP(x uint8) uint8 {
    return safer_ebox[(x) & 0xFF]
}

func LOG(x uint8) uint8 {
    return safer_lbox[(x) & 0xFF]
}

func PHT(x *uint8, y *uint8) {
    (*y) += (*x)
    (*x) += (*y)
}

func IPHT(x *uint8, y *uint8) {
    (*x) -= (*y)
    (*y) -= (*x)
}

func Safer_Expand_Userkey(
    userkey_1 []uint8,
    userkey_2 []uint8,
    nof_rounds uint32,
    strengthened int32,
    key []uint8,
) {
    var i, j, k uint32
    var ki int32
    var ka [SAFER_BLOCK_LEN + 1]uint8
    var kb [SAFER_BLOCK_LEN + 1]uint8

    if (SAFER_MAX_NOF_ROUNDS < nof_rounds) {
        nof_rounds = SAFER_MAX_NOF_ROUNDS
    }

    ki = 0

    key[ki] = uint8(nof_rounds)
    ki++

    ka[SAFER_BLOCK_LEN] = uint8(0)
    kb[SAFER_BLOCK_LEN] = uint8(0)

    k = 0
    for j = 0; j < SAFER_BLOCK_LEN; j++ {
        ka[j] = ROL8(userkey_1[j], 5)
        ka[SAFER_BLOCK_LEN] ^= ka[j]

        key[ki] = userkey_2[j]
        kb[j] = key[ki]
        ki++

        kb[SAFER_BLOCK_LEN] ^= kb[j]
    }

    for i = 1; i <= nof_rounds; i++ {
        for j = 0; j < SAFER_BLOCK_LEN + 1; j++ {
            ka[j] = ROL8(ka[j], 6)
            kb[j] = ROL8(kb[j], 6)
        }

        if strengthened > 0 {
            k = 2 * i - 1

            for k >= (SAFER_BLOCK_LEN + 1) {
                k -= SAFER_BLOCK_LEN + 1
            }
        }

        for j = 0; j < SAFER_BLOCK_LEN; j++ {
            if strengthened > 0 {
                key[ki] = (ka[k] + safer_ebox[int32(safer_ebox[int32((18 * i + j + 1)&0xFF)])]) & 0xFF
                ki++

                k++
                if k == (SAFER_BLOCK_LEN + 1) {
                    k = 0
                }
            } else {
                key[ki] = (ka[j] + safer_ebox[int32(safer_ebox[int32((18 * i + j + 1)&0xFF)])]) & 0xFF
                ki++
            }
        }

        if strengthened > 0 {
            k = 2 * i

            for k >= (SAFER_BLOCK_LEN + 1) {
                k -= SAFER_BLOCK_LEN + 1
            }
        }

        for j = 0; j < SAFER_BLOCK_LEN; j++ {
            if strengthened > 0 {
                key[ki] = (kb[k] + safer_ebox[int32(safer_ebox[int32((18 * i + j + 10)&0xFF)])]) & 0xFF
                ki++

                k++
                if k == (SAFER_BLOCK_LEN + 1) {
                    k = 0
                }
            } else {
                key[ki] = (kb[j] + safer_ebox[int32(safer_ebox[int32((18 * i + j + 10)&0xFF)])]) & 0xFF
                ki++
            }
        }
    }
}
