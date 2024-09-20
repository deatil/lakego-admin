package k12

// This is an implementation of KangarooTwelve
// at http://keccak.noekeon.org/kangarootwelve.html.

// The constructor requires a customization string.
func New(customString []byte) *digest {
    return newDigest(customString, 32)
}

// Sum returns the k12 checksum of the data.
func Sum(customString []byte, data []byte) (out [32]byte) {
    h := New(customString)
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// The constructor requires a customization string.
func NewWithSize(customString []byte, hashSize int) *digest {
    return newDigest(customString, hashSize)
}

// SumWithSize returns the k12 checksum of the data.
func SumWithSize(customString []byte, data []byte, hashSize int) (out []byte) {
    h := NewWithSize(customString, hashSize)
    h.Write(data)
    sum := h.Sum(nil)

    return sum
}
