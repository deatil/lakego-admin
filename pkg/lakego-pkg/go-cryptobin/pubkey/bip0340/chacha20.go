package bip0340

import (
    "errors"
)

const CHACHA20_MAX_ASKED_LEN = 64

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
