package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/blake2s"
)

// Blake2b_256 哈希值
func Blake2b_256(s string) string {
    sum := blake2b.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// Blake2b_256 哈希值
func (this Hash) Blake2b_256() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Blake2b_256(newData), nil
    })
}

// Blake2b_384 哈希值
func Blake2b_384(s string) string {
    sum := blake2b.Sum384([]byte(s))
    return hex.EncodeToString(sum[:])
}

// Blake2b_384 哈希值
func (this Hash) Blake2b_384() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Blake2b_384(newData), nil
    })
}

// Blake2b_512 哈希值
func Blake2b_512(s string) string {
    sum := blake2b.Sum512([]byte(s))
    return hex.EncodeToString(sum[:])
}

// Blake2b_512 哈希值
func (this Hash) Blake2b_512() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Blake2b_512(newData), nil
    })
}

// Blake2s_256 哈希值
func Blake2s_256(s string) string {
    sum := blake2s.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// Blake2s_256 哈希值
func (this Hash) Blake2s_256() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Blake2s_256(newData), nil
    })
}
