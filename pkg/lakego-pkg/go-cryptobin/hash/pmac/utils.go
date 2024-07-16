package pmac

import (
    "crypto/subtle"
)

// XOR the contents of b into a in-place
func xor(a, b []byte) {
    subtle.XORBytes(a, a, b)
}
