package rabin

import "testing"

func TestPolyMod(t *testing.T) {
    var p polyGF2
    for _, test := range [][3]uint64{
        {0x3e75, 0x3e75, 0x0},      // a(x) mod a(x) = 0
        {0x3e75 << 1, 0x3e75, 0x0}, // a(x)*x mod a(x) = 0
        {0x3e74, 0x3e75, 0x1},      // a(x) + 1 mod a(x) = 1
        {0x7337, 0xe39b, 0x7337},   // degree(a) < degree(b)
        // Random polynomials, checked with Wolfram Alpha.
        {0x3e75, 0x201b, 0x1e6e},
        {0xd10b, 0x35f7, 0x6d7},
        {0xe5a2, 0x8c83, 0x6921},
        {0x9a4a, 0xa8c7, 0x328d},
    } {
        a, b := newPolyGF2(test[0]), newPolyGF2(test[1])
        p.Mod(a, b)
        if p.coeff.Uint64() != test[2] {
            t.Errorf("%s mod %s = %s (%#x), want %s", a, b, &p, p.coeff.Uint64(), newPolyGF2(test[2]))
        }
    }
}
