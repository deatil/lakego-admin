// Package chaskey implements the Chaskey MAC
package chaskey

/*

http://mouha.be/chaskey/

https://eprint.iacr.org/2014/386.pdf
https://eprint.iacr.org/2015/1182.pdf

*/

// H holds keys for an instance of chaskey
type H struct {
    k  [4]uint32
    k1 [4]uint32
    k2 [4]uint32
    r  int
}

// New returns a new 8-round chaskey hasher.
func New(k [4]uint32) *H { return newH(k, 8) }

// New12 returns a new 12-round chaskey hasher.
func New12(k [4]uint32) *H { return newH(k, 12) }

func newH(k [4]uint32, rounds int) *H {

    h := H{
        k: k,
        r: rounds,
    }

    timestwo(h.k1[:], k[:])
    timestwo(h.k2[:], h.k1[:])

    return &h
}

// MAC computes the chaskey MAC of a message m.  The returned byte slice will be a subslice of tag, if provided.
func (h *H) MAC(m, tag []byte) []byte {

    if len(tag) < 16 {
        tag = make([]byte, 16)
    }

    chaskeyCore(h, m, tag)

    return tag[:16]
}

func timestwo(out []uint32, in []uint32) {
    var C = [2]uint32{0x00, 0x87}
    out[0] = (in[0] << 1) ^ C[in[3]>>31]
    out[1] = (in[1] << 1) | (in[0] >> 31)
    out[2] = (in[2] << 1) | (in[1] >> 31)
    out[3] = (in[3] << 1) | (in[2] >> 31)
}
