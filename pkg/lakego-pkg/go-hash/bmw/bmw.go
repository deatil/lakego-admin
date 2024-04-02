package bmw

// Sum returns the bmw-256 checksum of the data.
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum[:Size])
    return
}
