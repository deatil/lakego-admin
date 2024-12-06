package binary

import (
    "fmt"
    "math/bits"
    "encoding/binary"
)

func Rotl16(x, n uint16) uint16 {
    return bits.RotateLeft16(x, int(n))
}

func Rotr16(x, n uint16) uint16 {
    return Rotl16(x, 16 - n);
}

func Rotl32(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func Rotr32(x, n uint32) uint32 {
    return Rotl32(x, 32 - n);
}

func Rotl64(x, n uint64) uint64 {
    return bits.RotateLeft64(x, int(n))
}

func Rotr64(x, n uint64) uint64 {
    return Rotl64(x, 64 - n);
}

//==========

func LE2BE_16(inp []byte) []byte {
    i := binary.LittleEndian.Uint16(inp[0:])

    var sav [2]byte
    binary.BigEndian.PutUint16(sav[0:], i)

    return sav[:]
}

func BE2LE_16(inp []byte) []byte {
    i := binary.BigEndian.Uint16(inp[0:])

    var sav [2]byte
    binary.LittleEndian.PutUint16(sav[0:], i)

    return sav[:]
}

func LE2BE_32(inp []byte) []byte {
    i := binary.LittleEndian.Uint32(inp[0:])

    var sav [4]byte
    binary.BigEndian.PutUint32(sav[0:], i)

    return sav[:]
}

func BE2LE_32(inp []byte) []byte {
    i := binary.BigEndian.Uint32(inp[0:])

    var sav [4]byte
    binary.LittleEndian.PutUint32(sav[0:], i)

    return sav[:]
}

func LE2BE_64(inp []byte) []byte {
    i := binary.LittleEndian.Uint64(inp[0:])

    var sav [8]byte
    binary.BigEndian.PutUint64(sav[0:], i)

    return sav[:]
}

func BE2LE_64(inp []byte) []byte {
    i := binary.BigEndian.Uint64(inp[0:])

    var sav [8]byte
    binary.LittleEndian.PutUint64(sav[0:], i)

    return sav[:]
}

// =============

func LE2BE_16_Bytes(in []byte) []byte {
    if len(in) % 2 != 0 {
        panic(fmt.Sprintf("in data len(%d) error", len(in)))
    }

    out := make([]byte, len(in))

    // 小端转大端
    for i := 0; i < len(in); i += 2 {
        tmp := LE2BE_16(in[i:])
        copy(out[i:], tmp[:])
    }

    return out
}

func BE2LE_16_Bytes(in []byte) []byte {
    if len(in) % 2 != 0 {
        panic(fmt.Sprintf("in data len(%d) error", len(in)))
    }

    out := make([]byte, len(in))

    // 大端转小端
    for i := 0; i < len(in); i += 2 {
        tmp := BE2LE_16(in[i:])
        copy(out[i:], tmp[:])
    }

    return out
}

func LE2BE_32_Bytes(in []byte) []byte {
    if len(in) % 4 != 0 {
        panic(fmt.Sprintf("in data len(%d) error", len(in)))
    }

    out := make([]byte, len(in))

    // 小端转大端
    for i := 0; i < len(in); i += 4 {
        tmp := LE2BE_32(in[i:])
        copy(out[i:], tmp[:])
    }

    return out
}

func BE2LE_32_Bytes(in []byte) []byte {
    if len(in) % 4 != 0 {
        panic(fmt.Sprintf("in data len(%d) error", len(in)))
    }

    out := make([]byte, len(in))

    // 大端转小端
    for i := 0; i < len(in); i += 4 {
        tmp := BE2LE_32(in[i:])
        copy(out[i:], tmp[:])
    }

    return out
}

func LE2BE_64_Bytes(in []byte) []byte {
    if len(in) % 8 != 0 {
        panic(fmt.Sprintf("in data len(%d) error", len(in)))
    }

    out := make([]byte, len(in))

    // 小端转大端
    for i := 0; i < len(in); i += 8 {
        tmp := LE2BE_64(in[i:])
        copy(out[i:], tmp[:])
    }

    return out
}

func BE2LE_64_Bytes(in []byte) []byte {
    if len(in) % 8 != 0 {
        panic(fmt.Sprintf("in data len(%d) error", len(in)))
    }

    out := make([]byte, len(in))

    // 大端转小端
    for i := 0; i < len(in); i += 8 {
        tmp := BE2LE_64(in[i:])
        copy(out[i:], tmp[:])
    }

    return out
}
