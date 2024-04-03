package cubehash256

// Sum returns the cubehash checksum of the data.
func Sum(data []byte) (out [Size256]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum[:Size256])
    return
}
