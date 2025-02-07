package skeins

import (
    "encoding/binary"
)

func getu64(ptr []byte) uint64 {
    return binary.LittleEndian.Uint64(ptr)
}

func putu64(ptr []byte, a uint64) {
    binary.LittleEndian.PutUint64(ptr, a)
}
