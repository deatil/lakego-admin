//go:build go1.20
// +build go1.20

package memory

import (
	"unsafe"
)

func ConvertU32S(b []byte) []uint32 {
	sd := unsafe.SliceData(b)
	return unsafe.Slice((*uint32)(unsafe.Pointer(sd)), len(b)/4)
}

func P8(b []byte) *byte {
	sd := unsafe.SliceData(b)
	return sd
}
