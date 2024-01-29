package field

import (
    "crypto/subtle"
    "errors"
)

// Element is an integer modulo 2^256 - 2^224 - 2^96 + 2^64 - 1.
//
// The zero value is a valid zero element.
type Element struct {
    // Values are represented internally always in the Montgomery domain, and
    // converted in Bytes and SetBytes.
    x [4]uint64
}

const p256ElementLen = 32

type p256UntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *Element) One() *Element {
    p256SetOne(&e.x)
    return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *Element) Equal(t *Element) int {
    eBytes := e.Bytes()
    tBytes := t.Bytes()
    return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *Element) IsZero() int {
    zero := make([]byte, p256ElementLen)
    eBytes := e.Bytes()
    return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *Element) Set(t *Element) *Element {
    e.x = t.x
    return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *Element) Bytes() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [p256ElementLen]byte
    return e.bytes(&out)
}

func (e *Element) bytes(out *[p256ElementLen]byte) []byte {
    var tmp p256NonMontgomeryDomainFieldElement
    p256FromMontgomery(&tmp, &e.x)
    p256ToBytes(out, (*p256UntypedFieldElement)(&tmp))
    p256InvertEndianness(out[:])
    return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than 2^256 - 2^224 - 2^96 + 2^64 - 1,
// SetBytes returns nil and an error, and e is unchanged.
func (e *Element) SetBytes(v []byte) (*Element, error) {
    if len(v) != p256ElementLen {
        return nil, errors.New("cryptobin/sm2: invalid Element encoding")
    }

    // Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
    // the encoding of -1 mod p, so p - 1, the highest canonical encoding.
    var minusOneEncoding = new(Element).Sub(
        new(Element), new(Element).One()).Bytes()
    for i := range v {
        if v[i] < minusOneEncoding[i] {
            break
        }
        if v[i] > minusOneEncoding[i] {
            return nil, errors.New("cryptobin/sm2: invalid Element encoding")
        }
    }

    var in [p256ElementLen]byte
    copy(in[:], v)
    p256InvertEndianness(in[:])
    var tmp p256NonMontgomeryDomainFieldElement
    p256FromBytes((*p256UntypedFieldElement)(&tmp), &in)
    p256ToMontgomery(&e.x, &tmp)
    return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *Element) Add(t1, t2 *Element) *Element {
    p256Add(&e.x, &t1.x, &t2.x)
    return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *Element) Sub(t1, t2 *Element) *Element {
    p256Sub(&e.x, &t1.x, &t2.x)
    return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *Element) Mul(t1, t2 *Element) *Element {
    p256Mul(&e.x, &t1.x, &t2.x)
    return e
}

// Square sets e = t * t, and returns e.
func (e *Element) Square(t *Element) *Element {
    p256Square(&e.x, &t.x)
    return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
    p256Selectznz((*p256UntypedFieldElement)(&v.x), p256Uint1(cond),
        (*p256UntypedFieldElement)(&b.x), (*p256UntypedFieldElement)(&a.x))
    return v
}

func p256InvertEndianness(v []byte) {
    for i := 0; i < len(v)/2; i++ {
        v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
    }
}
