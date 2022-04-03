package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/sha3"
)

// Shake128 哈希值
func Shake128(s string, bits ...int) string {
    h := make([]byte, 64)
    sha3.ShakeSum128(h, []byte(s))

    data := hex.EncodeToString(h)

    useBits := 64
    if len(bits) > 0 {
        useBits = bits[0]
    }

    if useBits > len(data) {
        useBits = len(data)
    }

    return data[:useBits]
}

// Shake128 哈希值
func (this Hash) Shake128(bits ...int) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Shake128(newData, bits...), nil
    })
}

// Shake256 哈希值
func Shake256(s string, bits ...int) string {
    h := make([]byte, 64)
    sha3.ShakeSum256(h, []byte(s))

    data := hex.EncodeToString(h)

    useBits := 512
    if len(bits) > 0 {
        useBits = bits[0]
    }

    if useBits > len(data) {
        useBits = len(data)
    }

    return data[:useBits]
}

// Shake256 哈希值
func (this Hash) Shake256(bits ...int) Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Shake256(newData, bits...), nil
    })
}
