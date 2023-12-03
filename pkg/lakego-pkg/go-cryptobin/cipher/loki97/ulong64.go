package loki97

import (
    "encoding/binary"
)

type ULONG64 struct {
    l uint32
    r uint32
}

func add64(a ULONG64, b ULONG64) ULONG64 {
    var sum ULONG64

    sum.r = a.r + b.r
    sum.l = a.l + b.l

    if sum.r < b.r {
        sum.l++
    }

    return sum
}

func sub64(a ULONG64, b ULONG64) ULONG64 {
    var diff ULONG64

    diff.r = a.r - b.r
    diff.l = a.l - b.l

    if diff.r > a.r {
        diff.l--
    }

    return diff
}

// Endianness option
const littleEndian bool = false

func byteToULONG64(inp []byte) ULONG64 {
    var I ULONG64

    if littleEndian {
        I.l = binary.LittleEndian.Uint32(inp[0:])
        I.r = binary.LittleEndian.Uint32(inp[4:])
    } else {
        I.l = binary.BigEndian.Uint32(inp[0:])
        I.r = binary.BigEndian.Uint32(inp[4:])
    }

    return I
}

func ULONG64ToBYTE(I ULONG64) [8]byte {
    var sav [8]byte

    if littleEndian {
        binary.LittleEndian.PutUint32(sav[0:], I.l)
        binary.LittleEndian.PutUint32(sav[4:], I.r)
    } else {
        binary.BigEndian.PutUint32(sav[0:], I.l)
        binary.BigEndian.PutUint32(sav[4:], I.r)
    }

    return sav
}
