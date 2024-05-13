// Package rabin implements Rabin hashing (fingerprinting).
package rabin

import (
    "hash"
)

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

// New returns a new Rabin hash using the polynomial and window size
// represented by table.
func New(table *Table) hash.Hash64 {
    return newDigest(table)
}
