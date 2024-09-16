package bip0340

import (
    "hash"
    "math/big"
    "math/bits"
    "crypto/subtle"
    "encoding/binary"
)

const BIP0340_AUX       = "BIP0340/aux"
const BIP0340_NONCE	    = "BIP0340/nonce"
const BIP0340_CHALLENGE = "BIP0340/challenge"

var (
    zero = big.NewInt(0)
    one  = big.NewInt(1)
    two  = big.NewInt(2)
)

func getu32(ptr []byte) uint32 {
    return binary.LittleEndian.Uint32(ptr)
}

func putu32(ptr []byte, a uint32) {
    binary.LittleEndian.PutUint32(ptr, a)
}

func rotl(x, n uint32) uint32 {
    return bits.RotateLeft32(x, int(n))
}

func bigFromHex(s string) *big.Int {
    b, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("crypto/elliptic: internal error: invalid encoding")
    }
    return b
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
    return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

func bigintIsodd(a *big.Int) bool {
    aa := new(big.Int).Set(a)
    aa.Mod(aa, two)

    if aa.Cmp(zero) == 0 {
        return false
    }

    return true
}

func qround(a, b, c, d *uint32) {
    (*a) += (*b)
    (*d) ^= (*a)
    (*d) = rotl((*d), 16)
    (*c) += (*d)
    (*b) ^= (*c)
    (*b) = rotl((*b), 12)
    (*a) += (*b)
    (*d) ^= (*a)
    (*d) = rotl((*d), 8)
    (*c) += (*d)
    (*b) ^= (*c)
    (*b) = rotl((*b), 7)
}

func innerBlock(s []uint32) {
    qround(&s[0], &s[4], &s[ 8], &s[12])
    qround(&s[1], &s[5], &s[ 9], &s[13])
    qround(&s[2], &s[6], &s[10], &s[14])
    qround(&s[3], &s[7], &s[11], &s[15])
    qround(&s[0], &s[5], &s[10], &s[15])
    qround(&s[1], &s[6], &s[11], &s[12])
    qround(&s[2], &s[7], &s[ 8], &s[13])
    qround(&s[3], &s[4], &s[ 9], &s[14])
}

func bip0340Hash(tag []byte, m []byte, h hash.Hash) {
    h.Reset()
    h.Write(tag)
    hash := h.Sum(nil)

    /* Now compute hash(hash(tag) || hash(tag) || m) */
    h.Reset()
    h.Write(hash)
    h.Write(hash)
    h.Write(m)
}

/* Set the scalar value depending on the parity bit of the input
 * point y coordinate.
 */
func bip0340SetScalar(scalar, q *big.Int, py *big.Int) {
    /* Check if Py is odd or even */
    isodd := bigintIsodd(py)

    if isodd {
        /* Replace the input scalar by (q - scalar)
         * (its opposite modulo q)
         */
        scalar.Mod(scalar.Neg(scalar), q)
    }
}
