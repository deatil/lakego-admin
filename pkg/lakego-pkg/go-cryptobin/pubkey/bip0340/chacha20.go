package bip0340

import (
    "errors"
)

const CHACHA20_MAX_ASKED_LEN = 64

func qround(a, b, c, d *uint32) {
    (*a) += (*b)
    (*d) ^= (*a)
    (*d) = rotl((*d), 16)
    (*c) += (*d)
    (*b) ^= (*c)
    (*b) = rotl((*b), 12)
    (*a) += (*b)
    (*d) ^= (*a)
    (*d) = rotl((*d), 8)
    (*c) += (*d)
    (*b) ^= (*c)
    (*b) = rotl((*b), 7)
}

func innerBlock(s []uint32) {
    qround(&s[0], &s[4], &s[ 8], &s[12])
    qround(&s[1], &s[5], &s[ 9], &s[13])
    qround(&s[2], &s[6], &s[10], &s[14])
    qround(&s[3], &s[7], &s[11], &s[15])
    qround(&s[0], &s[5], &s[10], &s[15])
    qround(&s[1], &s[6], &s[11], &s[12])
    qround(&s[2], &s[7], &s[ 8], &s[13])
    qround(&s[3], &s[4], &s[ 9], &s[14])
}

func chacha20Block(key [32]byte, nonce [12]byte, blockCounter uint32, stream []byte) error {
    var state [16]uint32
    var initial_state [16]uint32
    var i uint

    if len(stream) > CHACHA20_MAX_ASKED_LEN {
        return errors.New("bip0340: stream is too long")
    }

    /* Initial state */
    state[0] = 0x61707865
    state[1] = 0x3320646e
    state[2] = 0x79622d32
    state[3] = 0x6b206574

    for i = 4; i < 12; i++ {
        state[i] = getu32(key[4 * (i - 4):])
    }

    state[12] = blockCounter
    for i = 13; i < 16; i++ {
       state[i] = getu32(nonce[4 * (i - 13):])
    }

    /* Core loop */
    copy(initial_state[:], state[:])
    for i = 0; i < 10; i++ {
        innerBlock(state[:])
    }

    /* Serialize and output the block */
    res := make([]byte, 64)
    for i = 0; i < 16; i++ {
        tmp := state[i] + initial_state[i]
        putu32(res[i*4:], tmp)
    }

    copy(stream, res)

    return nil
}
