package smkdf

import (
    "hash"
    "encoding/binary"
)

// Kdf key derivation function, compliance with GB/T 32918.4-2016 5.4.3.
// ANSI-X9.63-KDF
func Key(h func() hash.Hash, z []byte, size int) []byte {
    md := h()
    mdSize := md.Size()

    limit := uint64(size + mdSize - 1) / uint64(mdSize)
    if limit >= uint64(1 << mdSize) - 1 {
        panic("kdf: key length too long")
    }

    var countBytes [4]byte
    var count uint32 = 1
    var k []byte

    for i := 0; i < int(limit); i++ {
        binary.BigEndian.PutUint32(countBytes[:], count)

        md.Reset()
        md.Write(z)
        md.Write(countBytes[:])
        k = md.Sum(k)

        count++
    }

    return k[:size]
}
