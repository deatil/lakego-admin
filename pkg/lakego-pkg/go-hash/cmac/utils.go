package cmac

import (
    "crypto/subtle"
)

func shift(dst, src []byte) int {
    var b, bit byte
    for i := len(src) - 1; i >= 0; i-- { // a range would be nice
        bit = src[i] >> 7
        dst[i] = src[i]<<1 | b
        b = bit
    }

    return int(b)
}

// XOR the contents of b into a in-place
func xor(a, b []byte) {
    subtle.XORBytes(a, a, b)
}
