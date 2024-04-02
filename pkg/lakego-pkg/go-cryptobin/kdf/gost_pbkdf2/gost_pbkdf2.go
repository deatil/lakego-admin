package gost_pbkdf2

import (
    "hash"
    "bytes"
    "math/big"
    "crypto/subtle"
    "encoding/binary"
)

func Key(h func() hash.Hash, password, salt []byte, iterations, dklen int) (key []byte) {
    inner := h()
    outer := h()

    blockSize := inner.BlockSize()

    paddingSize := blockSize - len(password)%blockSize
    password = append(password, bytes.Repeat([]byte{0x00}, paddingSize)...)

    innerPassword := make([]byte, len(password))
    subtle.XORBytes(
        innerPassword,
        password,
        bytes.Repeat([]byte{0x36}, len(password)),
    )

    outerPassword := make([]byte, len(password))
    subtle.XORBytes(
        outerPassword,
        password,
        bytes.Repeat([]byte{0x5C}, len(password)),
    )

    var prf = func(msg []byte) []byte {
        inner.Reset()
        inner.Write(innerPassword)

        outer.Reset()
        outer.Write(outerPassword)

        inner.Write(msg)
        outer.Write(inner.Sum(nil))

        return outer.Sum(nil)
    }

    dkey := make([]byte, 0)
    rkeyBytes := make([]byte, inner.Size())
    pre, rkey := new(big.Int), new(big.Int)

    var prev []byte
    var loop uint32 = 1
    var loopBytes [4]byte

    for len(dkey) < dklen {
        binary.BigEndian.PutUint32(loopBytes[:], loop)

        prev = prf(append(salt, loopBytes[:]...))

        rkey.SetBytes(prev)

        for i := 0; i < iterations - 1; i++ {
            prev = prf(prev)
            rkey.Xor(rkey, pre.SetBytes(prev))
        }

        loop += 1

        rkey.FillBytes(rkeyBytes)
        dkey = append(dkey, rkeyBytes...)
    }

    return dkey[:dklen]
}

