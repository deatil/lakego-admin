//go:build !go1.20
// +build !go1.20

package memory

import (
    "reflect"
    "unsafe"
)

func ConvertU32S(b []byte) []uint32 {
    header := *(*reflect.SliceHeader)(unsafe.Pointer(&b)) //nolint:govet
    header.Len /= 4
    header.Cap /= 4
    return *(*[]uint32)(unsafe.Pointer(&header)) //nolint:govet
}

func P8(b []byte) *byte {
    header := *(*reflect.SliceHeader)(unsafe.Pointer(&b)) //nolint:govet
    return (*byte)(unsafe.Pointer(header.Data))
}
