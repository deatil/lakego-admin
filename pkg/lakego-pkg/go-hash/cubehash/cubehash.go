package cubehash

// Sum returns the cubehash checksum of the data.
// Sum as Sum512
func Sum(data []byte) (out [Size]byte) {
    h := New()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum[:Size])
    return
}

// Sum256 returns the cubehash checksum of the data.
func Sum256(data []byte) (out [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum[:Size256])
    return
}
