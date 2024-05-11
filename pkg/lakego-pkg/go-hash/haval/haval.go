package haval

import (
    "hash"
)

// New128_3 returns a new hash.Hash computing the haval-128_3 checksum
func New128_3() hash.Hash {
    h, _ := newDigest(128, 3)
    return h
}

// New128_4 returns a new hash.Hash computing the haval-128_4 checksum
func New128_4() hash.Hash {
    h, _ := newDigest(128, 4)
    return h
}

// New128_5 returns a new hash.Hash computing the haval-128_5 checksum
func New128_5() hash.Hash {
    h, _ := newDigest(128, 5)
    return h
}

// Sum128_3 returns the haval-128_3 checksum of the data.
func Sum128_3(data []byte) (out [Size128]byte) {
    h := New128_3()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum128_4 returns the haval-128_4 checksum of the data.
func Sum128_4(data []byte) (out [Size128]byte) {
    h := New128_4()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum128_5 returns the haval-128_5 checksum of the data.
func Sum128_5(data []byte) (out [Size128]byte) {
    h := New128_5()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New160_3 returns a new hash.Hash computing the haval-160_3 checksum
func New160_3() hash.Hash {
    h, _ := newDigest(160, 3)
    return h
}

// New160_4 returns a new hash.Hash computing the haval-160_4 checksum
func New160_4() hash.Hash {
    h, _ := newDigest(160, 4)
    return h
}

// New160_5 returns a new hash.Hash computing the haval-160_5 checksum
func New160_5() hash.Hash {
    h, _ := newDigest(160, 5)
    return h
}

// Sum160_3 returns the haval-160_3 checksum of the data.
func Sum160_3(data []byte) (out [Size160]byte) {
    h := New160_3()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum160_4 returns the haval-160_4 checksum of the data.
func Sum160_4(data []byte) (out [Size160]byte) {
    h := New160_4()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum160_5 returns the haval-160_5 checksum of the data.
func Sum160_5(data []byte) (out [Size160]byte) {
    h := New160_5()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New192_3 returns a new hash.Hash computing the haval-192_3 checksum
func New192_3() hash.Hash {
    h, _ := newDigest(192, 3)
    return h
}

// New192_4 returns a new hash.Hash computing the haval-192_4 checksum
func New192_4() hash.Hash {
    h, _ := newDigest(192, 4)
    return h
}

// New192_5 returns a new hash.Hash computing the haval-192_5 checksum
func New192_5() hash.Hash {
    h, _ := newDigest(192, 5)
    return h
}

// Sum192_3 returns the haval-192_3 checksum of the data.
func Sum192_3(data []byte) (out [Size192]byte) {
    h := New192_3()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum192_4 returns the haval-192_4 checksum of the data.
func Sum192_4(data []byte) (out [Size192]byte) {
    h := New192_4()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum192_5 returns the haval-192_5 checksum of the data.
func Sum192_5(data []byte) (out [Size192]byte) {
    h := New192_5()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New224_3 returns a new hash.Hash computing the haval-224_3 checksum
func New224_3() hash.Hash {
    h, _ := newDigest(224, 3)
    return h
}

// New224_4 returns a new hash.Hash computing the haval-224_4 checksum
func New224_4() hash.Hash {
    h, _ := newDigest(224, 4)
    return h
}

// New224_5 returns a new hash.Hash computing the haval-224_5 checksum
func New224_5() hash.Hash {
    h, _ := newDigest(224, 5)
    return h
}

// Sum224_3 returns the haval-224_3 checksum of the data.
func Sum224_3(data []byte) (out [Size224]byte) {
    h := New224_3()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum224_4 returns the haval-224_4 checksum of the data.
func Sum224_4(data []byte) (out [Size224]byte) {
    h := New224_4()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum224_5 returns the haval-224_5 checksum of the data.
func Sum224_5(data []byte) (out [Size224]byte) {
    h := New224_5()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// ===========

// New256_3 returns a new hash.Hash computing the haval-256_3 checksum
func New256_3() hash.Hash {
    h, _ := newDigest(256, 3)
    return h
}

// New256_4 returns a new hash.Hash computing the haval-256_4 checksum
func New256_4() hash.Hash {
    h, _ := newDigest(256, 4)
    return h
}

// New256_5 returns a new hash.Hash computing the haval-256_5 checksum
func New256_5() hash.Hash {
    h, _ := newDigest(256, 5)
    return h
}

// Sum256_3 returns the haval-256_3 checksum of the data.
func Sum256_3(data []byte) (out [Size256]byte) {
    h := New256_3()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum256_4 returns the haval-256_4 checksum of the data.
func Sum256_4(data []byte) (out [Size256]byte) {
    h := New256_4()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}

// Sum256_5 returns the haval-256_5 checksum of the data.
func Sum256_5(data []byte) (out [Size256]byte) {
    h := New256_5()
    h.Write(data)
    sum := h.Sum(nil)

    copy(out[:], sum)
    return
}
