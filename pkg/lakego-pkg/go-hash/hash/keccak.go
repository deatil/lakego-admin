package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/sha3"
)

// Keccak256 哈希值
func Keccak256(s ...string) string {
    d := sha3.NewLegacyKeccak256()
    for _, b := range s {
        d.Write([]byte(b))
    }

    return hex.EncodeToString(d.Sum(nil))
}

// Keccak256 哈希值
func (this Hash) Keccak256() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        var newData []string
        for _, v := range data {
            newData = append(newData, string(v))
        }

        return Keccak256(newData...), nil
    })
}

// Keccak512 哈希值
func Keccak512(s ...string) string {
    d := sha3.NewLegacyKeccak512()
    for _, b := range s {
        d.Write([]byte(b))
    }

    return hex.EncodeToString(d.Sum(nil))
}

// Keccak512 哈希值
func (this Hash) Keccak512() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        var newData []string
        for _, v := range data {
            newData = append(newData, string(v))
        }

        return Keccak512(newData...), nil
    })
}
