package memory

import (
    "unsafe"
)

// void pointer(byte b)
// if b is nil, panic
func VP8(b []byte) unsafe.Pointer {
    return unsafe.Pointer(&b[0])
}

// void pointer(uint32 b)
// if b is nil, panic
func VPU32(b []uint32) unsafe.Pointer {
    return unsafe.Pointer(&b[0])
}

// void pointer(uint64 b)
// if b is nil, panic
func VPU64(b []uint64) unsafe.Pointer {
    return unsafe.Pointer(&b[0])
}
