// Package rabin implements Rabin hashing (fingerprinting).
//
// A given Rabin hash function is defined by a polynomial over GF(2):
//
//   p(x) = ... + p₂x² + p₁x + p₀   where pₙ ∈ GF(2)
//
// The message to be hashed is likewise interpreted as a polynomial
// over GF(2), where the coefficients are the bits of the message in
// left-to-right most-significant-bit-first order. Given a message
// polynomial m(x) and a hashing polynomial p(x), the Rabin hash is
// simply the coefficients of m(x) mod p(x).
//
// Rabin hashing has the unusual property that it can efficiently
// compute a "rolling hash" of a stream of data, where the hash value
// reflects only the most recent w bytes of the stream, for some
// window size w. This property makes it ideal for "content-defined
// chunking", which sub-divides sequential data on boundaries that are
// robust to insertions and deletions.
//
// The details of Rabin hashing are described in Rabin, Michael
// (1981). "Fingerprinting by Random Polynomials." Center for Research
// in Computing Technology, Harvard University. Tech Report
// TR-CSE-03-01.
package rabin

// Poly64 is an 64-bit (degree 63) irreducible polynomial over GF(2).
//
// This is a convenient polynomial to use for computing 64-bit Rabin
// hashes.
const Poly64 = 0xbfe6b8a5bf378d83

// Table is a set of pre-computed tables for computing Rabin
// fingerprints for a given polynomial and window size.
type Table struct {
    push   [256]uint64
    pop    [256]uint64
    degree int
    shift  uint
    window int
}

// NewTable returns a Table for constructing Rabin hashes using the
// polynomial
//
//   p(x) = ... + p₂x² + p₁x + p₀   where pₙ ∈ GF(2)
//
// where pₙ = (polynomial >> n) & 1. This polynomial must be
// irreducible and must have degree >= 8. The number of bits in the
// resulting hash values will be the same as the number of bits in
// polynomial.
//
// This package defines Poly64 as a convenient 64-bit irreducible
// polynomial that can be used with this function.
//
// If window > 0, hashes constructed from this Table will be rolling
// hash over only the most recently written window bytes of data.
func NewTable(polynomial uint64, window int) *Table {
    tab := &Table{}
    p := newPolyGF2(polynomial)
    tab.degree = p.Degree()
    if tab.degree < 8 {
        panic("polynomial must have degree >= 8")
    }
    tab.shift = uint(tab.degree - 8)
    tab.window = window

    // Pre-compute the push table.
    var f, f2 polyGF2
    for i := 0; i < 256; i++ {
        // We shift out 8 bits of the hash at a time, so
        // pre-compute the update (i(x) * xⁿ mod p(x)) for all
        // possible top 8 bits of the hash.
        f.coeff.SetInt64(int64(i))
        f.MulX(&f, p.Degree())
        f2.Mod(&f, p)
        // To avoid explicitly masking away the bits that we
        // want to shift out of the hash, we add in (i(x) *
        // x^n). This is exactly equal to the bits we want to
        // mask out, so when we xor with this, it will take
        // care of zeroing out these bits.
        f.Add(&f, &f2)
        tab.push[i] = f.coeff.Uint64()
    }

    // Pre-compute the pop table.
    if window > 0 {
        for i := 0; i < 256; i++ {
            f.coeff.SetInt64(int64(i))
            f.MulX(&f, (window-1)*8)
            f2.Mod(&f, p)
            tab.pop[i] = f2.coeff.Uint64()
        }
    }

    return tab
}

// update updates the hash as if p had been appended to the currently
// hashed message.
func (tab *Table) update(hash uint64, p []byte) uint64 {
    // Given the current message
    //
    //   m(x) = ... + m₂x² + m₁x + m₀
    //
    // and hash
    //
    //   h(x) = m(x) mod p(x)
    //
    // we can extend the message by one bit b:
    //
    //   m'(x) = ... + m₂x³ + m₁x² + m₀x + b = m(x)*x + b
    //
    // This yields the hash update:
    //
    //   h'(x) = m'(x) mod p(x)
    //         = (m(x)*x + b) mod p(x)
    //         = ((m(x) mod p(x)) * x + b) mod p(x)
    //         = (h(x)*x + b) mod p(x)
    //         = hₙ₋₂xⁿ⁻¹ + ... + h₀x + b + hₙ₋₁(pₙ₋₁xⁿ⁻¹ + ... + p₀)
    //
    // where n is the degree of p(x).
    //
    // In general, we can extend the hash with any i bit message
    // m2 using the fact that
    //
    //   r(concat(m1, m2)) = r(r(m1) * r(xⁱ)) + r(m2)
    //
    // where r(M) = M(x) mod p(x). Below, we update it 8 bits at a
    // time and, since we require p(x) to have degree >= 8, this
    // simplifies to
    //
    //   r(concat(m1, m2)) = r(r(m1) * x⁸) + m2
    //
    // r(m1) is the current hash value. Multiplication by x⁸ is a
    // shift. We can compute r(r(m1) * x⁸) using the lookup table
    // we constructed in New.
    shift := tab.shift % 64 // shift%64 eliminates checks below
    for _, b := range p {
        top := uint8(hash >> shift)
        hash = (hash<<8 | uint64(b)) ^ tab.push[top]
    }

    return hash
}

// Hash computes Rabin hashes (often called fingerprints).
//
// Hash implements hash.Hash64.
type Hash struct {
    tab  *Table
    hash uint64
    msg  []byte
    pos  int
}

// New returns a new Rabin hash using the polynomial and window size
// represented by table.
func New(table *Table) *Hash {
    hash := &Hash{tab: table}
    if table.window > 0 {
        // Leading zeros don't affect the hash, so we can
        // start with a full window of zeros and keep the
        // later logic simpler.
        hash.msg = make([]byte, table.window)
    }

    return hash
}

// Reset resets h to its initial state.
func (h *Hash) Reset() {
    h.hash = 0
    if h.msg != nil {
        for i := range h.msg {
            h.msg[i] = 0
        }
        h.pos = 0
    }
}

// Size returns the number of bytes Sum will append. This is the
// minimum number of bytes necessary to represent the hash.
func (h *Hash) Size() int {
    bits := h.tab.degree + 1
    return (bits + 7) / 8
}

// BlockSize returns the window size if a window is configured, and
// otherwise returns 1.
//
// This satisfies the hash.Hash interface and indicates that Write is
// most efficient if writes are a multiple of the returned size.
func (h *Hash) BlockSize() int {
    if h.msg != nil {
        return len(h.msg)
    }

    return 1
}

// Write adds p to the running hash h.
//
// If h is windowed, this may also expire previously written bytes
// from the running hash so that h represents the hash of only the
// most recently written window bytes.
//
// It always returns len(p), nil.
func (h *Hash) Write(p []byte) (n int, err error) {
    n = len(p)

    if h.msg == nil {
        h.hash = h.tab.update(h.hash, p)
        return
    }

    window := len(h.msg)
    if len(p) >= window {
        // p covers the entire window. Discard our entire
        // state and just hash the last window bytes of p.
        p = p[len(p)-window:]
        copy(h.msg, p)

        h.pos, h.hash = 0, 0
        h.hash = h.tab.update(h.hash, p)
        return
    }

    // Add and remove bytes as we overwrite them in the window.
    tab := h.tab
    pos, hash, shift := h.pos, h.hash, tab.shift%64
    for _, b := range p {
        pop := h.msg[pos]
        h.msg[pos] = b
        if pos++; pos == window {
            pos = 0
        }

        hash ^= tab.pop[pop]
        top := uint8(hash >> shift)
        hash = (hash<<8 | uint64(b)) ^ tab.push[top]
    }

    h.pos, h.hash = int(pos), hash
    return
}

// Sum appends the least-significant byte first representation of the
// current hash to b and returns the resulting slice.
func (h *Hash) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *h
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (h *Hash) checkSum() []byte {
    var hbytes [8]byte
    for i := range hbytes {
        hbytes[i] = byte(h.hash >> uint(i*8))
    }

    return hbytes[:h.Size()]
}

// Sum64 returns the hash of all bytes written to h.
func (h *Hash) Sum64() uint64 {
    return h.hash
}
