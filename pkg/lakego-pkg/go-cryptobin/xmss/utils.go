package xmss

import "encoding/binary"

// If x and y are non-negative integers, we define Z = toBytes(x, y) to
// be the y-byte string containing the binary representation of x in
// big-endian byte order.
func toBytes(x, y int) (z []byte) {
    z = make([]byte, y)
    ux := uint64(x)

    var xByte byte
    for i := y - 1; i >= 0; i-- {
        xByte = byte(ux)
        z[i] = xByte & 0xff
        ux = ux >> 8
    }

    return
}

func fromBytes(x []byte, y int) (z uint64) {
    z = 0

    for i := 0; i < y; i++ {
        z |= uint64(x[i]) << (8 * uint32(y-1-i))
    }

    return
}

func bytesToUint32(in []byte) (out uint32) {
    out = binary.BigEndian.Uint32(in)
    return
}

func uint32ToBytes(in uint32) (out []byte) {
    out = make([]byte, 4)
    binary.BigEndian.PutUint32(out, in)
    return
}

func memsetByte(a []byte, v byte) {
    if len(a) == 0 {
        return
    }

    a[0] = v
    for bp := 1; bp < len(a); bp *= 2 {
        copy(a[bp:], a[:bp])
    }
}
