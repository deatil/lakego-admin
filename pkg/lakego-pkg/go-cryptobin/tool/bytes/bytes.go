package bytes

import (
    "unsafe"
    "crypto/subtle"
)

// Clone returns a copy of b[:len(b)].
// The result may have additional unused capacity.
func Clone(b []byte) []byte {
    if b == nil {
        return nil
    }

    return append([]byte{}, b...)
}

// GfnDouble computes 2 * input in the field of 2^n elements.
// The irreducible polynomial in the finite field for n=128 is
// x^128 + x^7 + x^2 + x + 1 (equals 0x87)
// Constant-time execution in order to avoid side-channel attacks
func GfnDouble(input []byte) []byte {
    if len(input) != 16 {
        panic("Doubling in GFn only implemented for n = 128")
    }

    // If the first bit is zero, return 2L = L << 1
    // Else return (L << 1) xor 0^120 10000111
    shifted := ShiftLeft(input)
    shifted[15] ^= ((input[0] >> 7) * 0x87)
    return shifted
}

// ShiftLeft outputs the byte array corresponding to x << 1 in binary.
func ShiftLeft(x []byte) []byte {
    l := len(x)
    dst := make([]byte, l)
    for i := 0; i < l-1; i++ {
        dst[i] = (x[i] << 1) | (x[i+1] >> 7)
    }

    dst[l-1] = x[l-1] << 1
    return dst
}

// ShiftLeftN puts in dst the byte array corresponding to x << n in binary.
func ShiftLeftN(dst, x []byte, n int) {
    // Erase first n / 8 bytes
    copy(dst, x[n/8:])

    // Shift the remaining n % 8 bits
    bits := uint(n % 8)
    l := len(dst)
    for i := 0; i < l-1; i++ {
        dst[i] = (dst[i] << bits) | (dst[i+1] >> uint(8-bits))
    }
    dst[l-1] = dst[l-1] << bits

    // Append trailing zeroes
    dst = append(dst, make([]byte, n/8)...)
}

// XORBytesMut assumes equal input length, replaces X with X XOR Y
func XORBytesMut(X, Y []byte) {
    subtle.XORBytes(X, X, Y)
}

// XORBytes assumes equal input length, puts X XOR Y into Z
func XORBytes(Z, X, Y []byte) {
    subtle.XORBytes(Z, X, Y)
}

// RightXOR XORs smaller input (assumed Y) at the right of the larger input (assumed X)
func RightXOR(X, Y []byte) []byte {
    offset := len(X) - len(Y)
    xored := make([]byte, len(X))

    copy(xored, X)

    subtle.XORBytes(xored[offset:], xored[offset:], Y)

    return xored
}

// split bytes with n length
func SplitSize(buf []byte, size int) [][]byte {
    var chunk []byte

    chunks := make([][]byte, 0, len(buf)/size+1)

    for len(buf) >= size {
        chunk, buf = buf[:size], buf[size:]
        chunks = append(chunks, chunk)
    }

    if len(buf) > 0 {
        chunks = append(chunks, buf[:])
    }

    return chunks
}

// string to bytes
func FromString(str string) []byte {
    return *(*[]byte)(unsafe.Pointer(
        &struct {
            string
            Cap int
        }{str, len(str)},
    ))
}

// bytes to string
func ToString(buf []byte) string {
    return *(*string)(unsafe.Pointer(&buf))
}
