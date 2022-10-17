package rc5

import (
    "crypto/cipher"
    "fmt"
    "unsafe"
)

// Reference: https://en.wikipedia.org/wiki/RC5
// http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the RC5 key, the wordSize arguement should be word size in bits,
// the r argument should be number of rounds.
func NewCipher(key []byte, wordSize, r uint) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, fmt.Errorf("rc5: invalid key size %d, we support 16/24/32 now", k)
    }
    
    if r < 8 || r > 127 {
        return nil, fmt.Errorf("rc5: invalid rounds %d, should be between 8 and 127", r)
    }
    
    switch wordSize {
        case 32:
            return newCipher32(key, r)
        case 64:
            return newCipher64(key, r)
        default:
            return nil, fmt.Errorf("rc5: unsupported word size %d, support 32/64 now", wordSize)
    }
}

// NewCipher32 creates and returns a new cipher.Block with 32 bits word size.
// The key argument should be the RC5 key, the r argument should be number of rounds.
func NewCipher32(key []byte, r uint) (cipher.Block, error) {
    return NewCipher(key, 32, r)
}

// NewCipher64 creates and returns a new cipher.Block with 64 bits word size.
// The key argument should be the RC5 key, the r argument should be number of rounds.
func NewCipher64(key []byte, r uint) (cipher.Block, error) {
    return NewCipher(key, 64, r)
}

// anyOverlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
func anyOverlap(x, y []byte) bool {
    return len(x) > 0 && len(y) > 0 &&
        uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
        uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// inexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// inexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func inexactOverlap(x, y []byte) bool {
    if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
        return false
    }
    return anyOverlap(x, y)
}
