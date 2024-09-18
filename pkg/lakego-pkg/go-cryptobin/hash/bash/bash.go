package bash

import (
    "hash"
)

/*
 * This is an implementation of the BASH hash functions family (for sizes 224, 256, 384 and 512)
 * following the standard STB 34.101.77-2020 (http://apmi.bsu.by/assets/files/std/bash-spec24.pdf).
 * An english version of the specifications exist here: https://eprint.iacr.org/2016/587.pdf
 */

// New224 returns a new hash.Hash computing the Bash checksum
func New224() hash.Hash {
    h, _ := New(224)
    return h
}

// New256 returns a new hash.Hash computing the Bash checksum
func New256() hash.Hash {
    h, _ := New(256)
    return h
}

// New384 returns a new hash.Hash computing the Bash checksum
func New384() hash.Hash {
    h, _ := New(384)
    return h
}

// New512 returns a new hash.Hash computing the Bash checksum
func New512() hash.Hash {
    h, _ := New(512)
    return h
}

// Sum224 returns the Bash-224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
    h := New224()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum224[:], sum[:Size224])
    return
}

// Sum256 returns the Bash-256 checksum of the data.
func Sum256(data []byte) (sum256 [Size256]byte) {
    h := New256()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum256[:], sum[:Size256])
    return
}

// Sum384 returns the Bash-384 checksum of the data.
func Sum384(data []byte) (sum384 [Size384]byte) {
    h := New384()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum384[:], sum[:Size384])
    return
}

// Sum512 returns the Bash-512 checksum of the data.
func Sum512(data []byte) (sum512 [Size512]byte) {
    h := New512()
    h.Write(data)
    sum := h.Sum(nil)

    copy(sum512[:], sum[:Size512])
    return
}
