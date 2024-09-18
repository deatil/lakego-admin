package bash

import (
    "encoding/binary"
)

const BASH_SLICES_X   = 3
const BASH_SLICES_Y   = 8
const BASH_ROT_ROUNDS = 8
const BASH_ROT_IDX    = 4
const BASH_ROUNDS     = 24

// Endianness option
const littleEndian bool = false

func getu64(ptr []byte) uint64 {
    if littleEndian {
        return binary.LittleEndian.Uint64(ptr)
    } else {
        return binary.BigEndian.Uint64(ptr)
    }
}

func putu64(ptr []byte, a uint64) {
    if littleEndian {
        binary.LittleEndian.PutUint64(ptr, a)
    } else {
        binary.BigEndian.PutUint64(ptr, a)
    }
}

func bytesToUint64s(b []byte) []uint64 {
    size := len(b) / 8
    dst := make([]uint64, size)

    for i := 0; i < size; i++ {
        j := i * 8

        if littleEndian {
            dst[i] = binary.LittleEndian.Uint64(b[j:])
        } else {
            dst[i] = binary.BigEndian.Uint64(b[j:])
        }
    }

    return dst
}

func uint64sToBytes(w []uint64) []byte {
    size := len(w) * 8
    dst := make([]byte, size)

    for i := 0; i < len(w); i++ {
        j := i * 8

        if littleEndian {
            binary.LittleEndian.PutUint64(dst[j:], w[i])
        } else {
            binary.BigEndian.PutUint64(dst[j:], w[i])
        }
    }

    return dst
}

func _BASH_ROTHI_(x, y uint64) uint64 {
    return x << y | x >> (64 - y)
}

func BASH_ROTHI(x, y uint64) uint64 {
    if (y < (8 * 8)) && (y > 0) {
        return _BASH_ROTHI_(x, y)
    }

    return x
}

func BASH_L3_S3(W0, W1, W2 *uint64, m1, n1, m2, n2 uint64) {
    var T0, T1, T2 uint64

    T0 = BASH_ROTHI((*W0), m1)
    (*W0) = ((*W0) ^ (*W1) ^ (*W2))
    T1 = ((*W1) ^ BASH_ROTHI((*W0), n1))
    (*W1) = (T0 ^ T1)
    (*W2) = ((*W2) ^ BASH_ROTHI((*W2), m2) ^ BASH_ROTHI(T1, n2))
    T0 = (^(*W2))
    T1 = ((*W0) | (*W2))
    T2 = ((*W0) & (*W1))
    T0 = (T0 | (*W1))
    (*W1) = ((*W1) ^ T1)
    (*W2) = ((*W2) ^ T2)
    (*W0) = ((*W0) ^ T0)
}

func BASH_PERMUTE(S []uint64) {
    var S_ = [BASH_SLICES_X * BASH_SLICES_Y]uint64{}

    var _ = S[23]
    copy(S_[:], S[:])

    S[ 0] = S_[15]; S[ 1] = S_[10]; S[ 2] = S_[ 9]; S[ 3] = S_[12]
    S[ 4] = S_[11]; S[ 5] = S_[14]; S[ 6] = S_[13]; S[ 7] = S_[ 8]
    S[ 8] = S_[17]; S[ 9] = S_[16]; S[10] = S_[19]; S[11] = S_[18]
    S[12] = S_[21]; S[13] = S_[20]; S[14] = S_[23]; S[15] = S_[22]
    S[16] = S_[ 6]; S[17] = S_[ 3]; S[18] = S_[ 0]; S[19] = S_[ 5]
    S[20] = S_[ 2]; S[21] = S_[ 7]; S[22] = S_[ 4]; S[23] = S_[ 1]
}

func SWAP64(A *uint64) {
    (*A) = ((*A) << 56 | ((*A) & 0xff00) << 40 | ((*A) & 0xff0000) << 24 |
        ((*A) & 0xff000000) << 8 | ((*A) >> 8 & 0xff000000) |
        ((*A) >> 24 & 0xff0000) | ((*A) >> 40 & 0xff00) | (*A) >> 56)
}

func BASHF(S []uint64, bigend bool) {
    var round, i int

    /* Swap endianness if necessary */
    if bigend {
        for i = 0; i < (BASH_SLICES_X * BASH_SLICES_Y); i++ {
            SWAP64(&S[i])
        }
    }

    for round = 0; round < BASH_ROUNDS; round++ {
        for v := 0; v < 8; v++ {
            BASH_L3_S3(
                &S[v], &S[v+8], &S[v+16],
                uint64(bash_rot[v][0]),
                uint64(bash_rot[v][1]),
                uint64(bash_rot[v][2]),
                uint64(bash_rot[v][3]),
            )
        }

        BASH_PERMUTE(S)
        S[23] ^= bash_rc[round]
    }

    /* Swap back endianness if necessary */
    if bigend {
        for i = 0; i < (BASH_SLICES_X * BASH_SLICES_Y); i++ {
            SWAP64(&S[i])
        }
    }
}
