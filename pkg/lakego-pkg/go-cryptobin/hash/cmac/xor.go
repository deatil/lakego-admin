// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build !amd64

package cmac

// xor xors the bytes in dst with src and writes the result to dst.
// The destination is assumed to have enough space.
func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}
