// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//go:build arm64 && !generic
// +build arm64,!generic

package xor

// xorBytes xors the bytes in a and b. The destination should have enough
// space, otherwise xorBytes will panic. Returns the number of bytes xor'd.
func XorBytes(dst, a, b []byte) int {
    n := len(a)
    if len(b) < n {
        n = len(b)
    }
    if n == 0 {
        return 0
    }
    // make sure dst has enough space
    _ = dst[n-1]

    xorBytesARM64(&dst[0], &a[0], &b[0], n)
    return n
}

func XorWords(dst, a, b []byte) {
    XorBytes(dst, a, b)
}

//go:noescape
func xorBytesARM64(dst, a, b *byte, n int)
