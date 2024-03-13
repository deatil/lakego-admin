// Package haraka implements the Haraka v2 family of hash functions
// presented in:
//
// Haraka v2 – Efficient Short-Input Hashing for
// Post-Quantum Applications
//
// by Stefan Kolbl, Martin M. Lauridsen, Florian Mendel,
// and Christian Rechberger
//
// https://eprint.iacr.org/2016/098.pdf
//
// These functions are designed to be fast for fixed-length (512/256-bit)
// inputs on processors with AES instructions.  A primary use case is for
// hash-based signatures in post-quantum cryptography.  Note, that if your
// processor does not have AES instructions then the performance will be
// ~10x slower due to software emulation of the AES round function. Currently,
// AES instruction optimization is only implemented for amd64 processors.
package haraka

var hasAES = false

// Haraka256 calculates the Harakaa v2 hash of a 256-bit
// input and places the 256-bit result in output.
func Haraka256(output, input *[32]byte) {
    if hasAES {
        haraka256AES(&rc[0], &output[0], &input[0])
    } else {
        haraka256Ref(output, input)
    }
}

// Haraka512 calculates the Harakaa v2 hash of a 512-bit
// input and places the 256-bit result in output.
func Haraka512(output *[32]byte, input *[64]byte) {
    if hasAES {
        haraka512AES(&rc[0], &output[0], &input[0])
    } else {
        haraka512Ref(output, input)
    }
}

func haraka256AES(rc *uint32, dst, src *byte)
func haraka512AES(rc *uint32, dst, src *byte)
