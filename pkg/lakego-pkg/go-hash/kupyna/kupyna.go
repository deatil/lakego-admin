package kupyna

// Sum256 returns the Kupyna-256 checksum of the data.
func Sum256(data []byte) (sum [Size256]byte) {
    h := New256()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

// Sum384 returns the Kupyna-384 checksum of the data.
func Sum384(data []byte) (sum [Size384]byte) {
    h := New384()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

// Sum512 returns the Kupyna-512 checksum of the data.
func Sum512(data []byte) (sum [Size512]byte) {
    h := New512()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}
