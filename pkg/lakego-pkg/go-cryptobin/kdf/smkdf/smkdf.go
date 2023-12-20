package smkdf

import (
    "hash"
    "encoding/binary"
)

// Kdf key derivation function, compliance with GB/T 32918.4-2016 5.4.3.
// ANSI-X9.63-KDF
func Key(h func() hash.Hash, z []byte, size int) []byte {
    md := h()

    limit := uint64(size + md.Size() - 1) / uint64(md.Size())
    if limit >= uint64(1 << 32) - 1 {
        panic("kdf: key length too long")
    }

    var countBytes [4]byte
    var ct uint32 = 1
    var k []byte

    for i := 0; i < int(limit); i++ {
        binary.BigEndian.PutUint32(countBytes[:], ct)

        md.Write(z)
        md.Write(countBytes[:])
        k = md.Sum(k)

        ct++

        md.Reset()
    }

    return k[:size]
}
