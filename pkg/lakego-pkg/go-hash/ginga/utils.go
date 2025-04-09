package ginga

import (
    "math/bits"
    "encoding/binary"
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func putu64(ptr []byte, a uint64) {
    binary.LittleEndian.PutUint64(ptr, a)
}

func rotl32(x uint32, n int) uint32 {
    return bits.RotateLeft32(x, n)
}

func confuse32(x uint32) uint32 {
    x ^= 0xA5A5A5A5
    x += 0x3C3C3C3C
    x = rotl32(x, 7)
    return x
}

func round32(x, k uint32, r int) uint32 {
    x += k
    x = confuse32(x)
    x = rotl32(x, (r+3)&31)
    x ^= k
    x = rotl32(x, (r+5)&31)
    return x
}

func subKey32(k [4]uint32, round, i int) uint32 {
    base := k[(i+round)&3]
    return rotl32(base^uint32(i*73+round*91), (round+i)&31)
}

func mixState256(state *[8]uint32) {
    for i := 0; i < 8; i++ {
        state[i] ^= rotl32(state[(i+1)&7], (5*i+11)&31)
    }
}
