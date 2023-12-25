//go:build (!amd64 && !arm64) || purego

package sm9curve

import (
    "math/bits"
)

func gfpCarry(a *gfP, head uint64) {
    b := &gfP{}

    var carry uint64
    for i, pi := range p2 {
        b[i], carry = bits.Sub64(a[i], pi, carry)
    }
    carry = carry &^ head

    // If b is negative, then return a.
    // Else return b.
    carry = -carry
    ncarry := ^carry
    for i := 0; i < 4; i++ {
        a[i] = (a[i] & carry) | (b[i] & ncarry)
    }
}

func gfpNeg(c, a *gfP) {
    var carry uint64
    for i, pi := range p2 {
        c[i], carry = bits.Sub64(pi, a[i], carry)
    }
    // required for "zero", bn256 treat infinity point as valid
    gfpCarry(c, 0)
}

func gfpAdd(c, a, b *gfP) {
    var carry uint64
    for i, ai := range a {
        c[i], carry = bits.Add64(ai, b[i], carry)
    }
    gfpCarry(c, carry)
}

func gfpSub(c, a, b *gfP) {
    t := &gfP{}

    var carry, underflow uint64

    for i, ai := range a {
        c[i], underflow = bits.Sub64(ai, b[i], underflow)
    }

    for i, pi := range p2 {
        t[i], carry = bits.Add64(pi, c[i], carry)
    }

    mask := -underflow
    for i, ci := range c {
        c[i] ^= mask & (ci ^ t[i])
    }
}

// addMulVVW multiplies the multi-word value x by the single-word value y,
// adding the result to the multi-word value z and returning the final carry.
// It can be thought of as one row of a pen-and-paper column multiplication.
func addMulVVW(z, x []uint64, y uint64) (carry uint64) {
    _ = x[len(z)-1] // bounds check elimination hint
    for i := range z {
        hi, lo := bits.Mul64(x[i], y)
        lo, c := bits.Add64(lo, z[i], 0)
        // We use bits.Add with zero to get an add-with-carry instruction that
        // absorbs the carry from the previous bits.Add.
        hi, _ = bits.Add64(hi, 0, c)
        lo, c = bits.Add64(lo, carry, 0)
        hi, _ = bits.Add64(hi, 0, c)
        carry = hi
        z[i] = lo
    }
    return carry
}

func gfpMul(c, a, b *gfP) {
    var T [8]uint64
    // This loop implements Word-by-Word Montgomery Multiplication, as
    // described in Algorithm 4 (Fig. 3) of "Efficient Software
    // Implementations of Modular Exponentiation" by Shay Gueron
    // [https://eprint.iacr.org/2011/239.pdf].
    var carry uint64
    for i := 0; i < 4; i++ {
        // Step 1 (T = a × b) is computed as a large pen-and-paper column
        // multiplication of two numbers with n base-2^_W digits. If we just
        // wanted to produce 2n-wide T, we would do
        //
        //   for i := 0; i < n; i++ {
        //       d := bLimbs[i]
        //       T[n+i] = addMulVVW(T[i:n+i], aLimbs, d)
        //   }
        //
        // where d is a digit of the multiplier, T[i:n+i] is the shifted
        // position of the product of that digit, and T[n+i] is the final carry.
        // Note that T[i] isn't modified after processing the i-th digit.
        //
        // Instead of running two loops, one for Step 1 and one for Steps 2–6,
        // the result of Step 1 is computed during the next loop. This is
        // possible because each iteration only uses T[i] in Step 2 and then
        // discards it in Step 6.
        d := b[i]

        c1 := addMulVVW(T[i:4+i], a[:], d)

        // Step 6 is replaced by shifting the virtual window we operate
        // over: T of the algorithm is T[i:] for us. That means that T1 in
        // Step 2 (T mod 2^_W) is simply T[i]. k0 in Step 3 is our m0inv.
        Y := T[i] * np[0]

        // Step 4 and 5 add Y × m to T, which as mentioned above is stored
        // at T[i:]. The two carries (from a × d and Y × m) are added up in
        // the next word T[n+i], and the carry bit from that addition is
        // brought forward to the next iteration.
        c2 := addMulVVW(T[i:4+i], p2[:], Y)
        T[4+i], carry = bits.Add64(c1, c2, carry)
    }

    *c = gfP{T[4], T[5], T[6], T[7]}
    gfpCarry(c, carry)
}
