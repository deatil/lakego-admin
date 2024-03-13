// Package threefish implements the Threefish tweakable block cipher.
package threefish

import (
    "fmt"
    "encoding/binary"
)

// Threefish is a block cipher that was developed as part of the Skein hash
// function as a submission to the NIST hash function competition. Threefish
// supports block sizes of 256, 512, and 1024 bits.
//
// For the full Threefish specification, see [1].
//
// Test vectors were extracted from the latest reference implementation [2].
//
// Encryption and decryption loops have been unrolled to contain eight rounds
// in each iteration. This allows rotation constants to be embedded in the code
// without being repeated. This practice is described in detail in the paper [1]
// which also provides detailed performance information.
//
// [1] http://www.skein-hash.info/sites/default/files/skein1.3.pdf
// [2] http://www.skein-hash.info/sites/default/files/NIST_CD_102610.zip

const (
    // Size of the tweak value in bytes, as expected from the user
    tweakSize int = 16

    // Constant used to ensure that key extension cannot result in all zeroes
    c240 uint64 = 0x1bd11bdaa9fc1a22
)

// Aliases to help produce concise code
var (
    loadWord  = binary.LittleEndian.Uint64
    storeWord = binary.LittleEndian.PutUint64
)

// A KeySizeError is returned when the provided key isn't the correct size.
type KeySizeError int

// Error describes a KeySizeError.
func (e KeySizeError) Error() string {
    return fmt.Sprintf("cryptobin/threefish: key size must be %d bytes", e)
}

// A TweakSizeError is returned when the provided tweak isn't the correct size.
type TweakSizeError struct{}

// Error describes a TweakSizeError.
func (e TweakSizeError) Error() string {
    return fmt.Sprintf("cryptobin/threefish: tweak size must be %d bytes", tweakSize)
}

// calculateTweak loads a tweak value from src and extends it into dst.
func calculateTweak(dst *[(tweakSize / 8) + 1]uint64, src []byte) error {
    if len(src) != tweakSize {
        return new(TweakSizeError)
    }

    dst[0] = loadWord(src[0:8])
    dst[1] = loadWord(src[8:16])
    dst[2] = dst[0] ^ dst[1]

    return nil
}
