// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64, !gccgo, !appengine

package cmac

import "unsafe"

const wordSize = int(unsafe.Sizeof(uintptr(0)))

// xor xors the bytes in dst with src and writes the result to dst.
// The destination is assumed to have enough space.
func xor(dst, src []byte) {
	n := len(src)

	w := n / wordSize
	if w > 0 {
		dstPtr := *(*[]uintptr)(unsafe.Pointer(&dst))
		srcPtr := *(*[]uintptr)(unsafe.Pointer(&src))
		for i, v := range srcPtr[:w] {
			dstPtr[i] ^= v
		}
	}

	for i := (n & (^(wordSize - 1))); i < n; i++ {
		dst[i] ^= src[i]
	}
}
