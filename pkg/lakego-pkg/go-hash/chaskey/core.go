package chaskey

import (
    "math/bits"
    "encoding/binary"
)

func chaskeyCore(h *H, m []byte, tag []byte) {

    v0, v1, v2, v3 := h.k[0], h.k[1], h.k[2], h.k[3]

    for ; len(m) > 16; m = m[16:] {

        v0 ^= binary.LittleEndian.Uint32(m[0:4])
        v1 ^= binary.LittleEndian.Uint32(m[4:8])
        v2 ^= binary.LittleEndian.Uint32(m[8:12])
        v3 ^= binary.LittleEndian.Uint32(m[12:16])

        // permute
        for i := 0; i < h.r; i++ {
            // round
            v0 += v1
            v2 += v3
            v1 = bits.RotateLeft32(v1, 5)
            v3 = bits.RotateLeft32(v3, 8)
            v1 ^= v0
            v3 ^= v2
            v0 = bits.RotateLeft32(v0, 16)
            v0 += v3
            v2 += v1
            v3 = bits.RotateLeft32(v3, 13)
            v1 = bits.RotateLeft32(v1, 7)
            v3 ^= v0
            v1 ^= v2
            v2 = bits.RotateLeft32(v2, 16)
        }
    }

    var l [4]uint32
    var lastblock [4]uint32

    if len(m) == 16 {
        l = h.k1

        lastblock[0] = binary.LittleEndian.Uint32(m[0:4])
        lastblock[1] = binary.LittleEndian.Uint32(m[4:8])
        lastblock[2] = binary.LittleEndian.Uint32(m[8:12])
        lastblock[3] = binary.LittleEndian.Uint32(m[12:16])

    } else {
        l = h.k2
        var lb [16]byte
        copy(lb[:], m)

        lb[len(m)] = 0x01

        lastblock[0] = binary.LittleEndian.Uint32(lb[0:4])
        lastblock[1] = binary.LittleEndian.Uint32(lb[4:8])
        lastblock[2] = binary.LittleEndian.Uint32(lb[8:12])
        lastblock[3] = binary.LittleEndian.Uint32(lb[12:16])
    }

    v0 ^= lastblock[0]
    v1 ^= lastblock[1]
    v2 ^= lastblock[2]
    v3 ^= lastblock[3]

    v0 ^= l[0]
    v1 ^= l[1]
    v2 ^= l[2]
    v3 ^= l[3]

    // permute
    for i := 0; i < h.r; i++ {
        // round
        v0 += v1
        v2 += v3
        v1 = bits.RotateLeft32(v1, 5)
        v3 = bits.RotateLeft32(v3, 8)
        v1 ^= v0
        v3 ^= v2
        v0 = bits.RotateLeft32(v0, 16)
        v0 += v3
        v2 += v1
        v3 = bits.RotateLeft32(v3, 13)
        v1 = bits.RotateLeft32(v1, 7)
        v3 ^= v0
        v1 ^= v2
        v2 = bits.RotateLeft32(v2, 16)
    }

    v0 ^= l[0]
    v1 ^= l[1]
    v2 ^= l[2]
    v3 ^= l[3]

    _ = tag[15]

    binary.LittleEndian.PutUint32(tag[0:4], v0)
    binary.LittleEndian.PutUint32(tag[4:8], v1)
    binary.LittleEndian.PutUint32(tag[8:12], v2)
    binary.LittleEndian.PutUint32(tag[12:16], v3)

}
