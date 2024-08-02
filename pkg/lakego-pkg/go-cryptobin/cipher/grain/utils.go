package grain

import (
    "fmt"
    "strings"
    "math/bits"
)

func next(s *state) uint32 {
    return nextGeneric(s)
}

func accumulate(reg, acc uint64, ms, pt uint16) (uint64, uint64) {
    return accumulateGeneric(reg, acc, ms, pt)
}

func getmb(num uint32) uint16 {
    const (
        mvo0 = 0x22222222
        mvo1 = 0x18181818
        mvo2 = 0x07800780
        mvo3 = 0x007f8000
        mvo4 = 0x80000000
    )

    // 0xAAA... extracts the odd MAC bits, LSB first.
    x := uint32(num & 0xAAAAAAAA)
    // Inlining the "t = mvoX" assignments allows the compiler to
    // inline getmb itself, because as of Go 1.16 the compiler
    // still judges the complexity of a function based on the
    // number of *lexical* statements.
    x = (x ^ (x & mvo0)) | (x&mvo0)>>1
    x = (x ^ (x & mvo1)) | (x&mvo1)>>2
    x = (x ^ (x & mvo2)) | (x&mvo2)>>4
    x = (x ^ (x & mvo3)) | (x&mvo3)>>8
    x = (x ^ (x & mvo4)) | (x&mvo4)>>16
    return uint16(x)
}

func getkb(num uint32) uint16 {
    const (
        mve0 = 0x44444444
        mve1 = 0x30303030
        mve2 = 0x0f000f00
        mve3 = 0x00ff0000
    )

    var t uint32
    // 0x555... extracts the even key bits, LSB first.
    x := uint32(num & 0x55555555)
    t = x & mve0
    x = (x ^ t) | (t >> 1)
    t = x & mve1
    x = (x ^ t) | (t >> 2)
    t = x & mve2
    x = (x ^ t) | (t >> 4)
    t = x & mve3
    x = (x ^ t) | (t >> 8)
    return uint16(x)
}

// shortInt is the largest allowed integer for DER's "short"
// encoding.
const shortInt = 127

// der is a DER-encoded integer using the definite form.
type der [10]byte

// len returns the number of bytes used in d.
func (d der) len() int {
    // d[0] encodes the number of following bytes, so add one.
    return int(d[0]&^0x80) + 1
}

// encode encodes the length x using DER's definite form for
// x > shortInt.
//
// encode returns an even number of bytes to make the call site
// easier.
func encode(x int) (d der) {
    n := (bits.Len(uint(x)) + 7) / 8
    d[0] = byte(0x80 | n)
    for i := n; i > 0; i-- {
        d[i] = byte(n)
        n >>= 8
    }
    return d
}

// lfsr is a 128-bit LFSR.
//
// New input is added in the high 32 bits, shifting old bits off
// the front.
type lfsr struct {
    lo, hi uint64
}

type nfsr = lfsr

// shift shifts off 32 low bits and replaces the high bits with
// x:
//
//    u = (u >> 32) | (x << 96)
//
func (r lfsr) shift(x uint32) lfsr {
    const s = 32
    lo := r.lo>>s | r.hi<<(64-s)
    hi := r.hi>>s | uint64(x)<<s
    return lfsr{lo, hi}
}

// xor XORs the high 32 bits with x.
func (r lfsr) xor(x uint32) lfsr {
    const mask = 1<<32 - 1
    hi32 := uint32(r.hi>>32) ^ x
    hi := uint64(hi32)<<32 | r.hi&mask
    return lfsr{r.lo, hi}
}

// words returns the state of the LFSR as 64-bit words.
//
// Each word is offset 32 bits:
//
//    u0: [0, 64)
//    u1: [32, 96)
//    u2: [64, 128)
//    u3: [96, 128)
//
func (r lfsr) words() (u0, u1, u2, u3 uint64) {
    u0 = r.lo                // 0,1
    u1 = r.lo>>32 | r.hi<<32 // 1,2
    u2 = r.hi                // 2,3
    u3 = r.hi >> 32          // 3,x
    return
}

func (r lfsr) String() string {
    var b strings.Builder
    b.WriteByte('[')
    fmt.Fprintf(&b, "%#x ", uint32(r.lo))
    fmt.Fprintf(&b, "%#x ", uint32(r.lo>>32))
    fmt.Fprintf(&b, "%#x ", uint32(r.hi))
    fmt.Fprintf(&b, "%#x", uint32(r.hi>>32))
    b.WriteByte(']')
    return b.String()
}
