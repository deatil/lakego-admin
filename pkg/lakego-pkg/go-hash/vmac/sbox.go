package vmac

import (
    "math/big"
)

const (
    l1keylen  = 1024
    l1keysize = l1keylen / 8
)

var (
    one    = big.NewInt(1)
    m64    = new(big.Int).Lsh(one, 64)                                                                                             // 2^64
    m126   = new(big.Int).Lsh(one, 126)                                                                                            // 2^126
    m128   = new(big.Int).Lsh(one, 128)                                                                                            // 2^128
    p64    = bytesToBigint([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF})                                                 // 2^64 - 257
    p64p32 = bytesToBigint([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00})                                                 // 2^64 - 2^32
    p127   = bytesToBigint([]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // 2^127 - 1
)
