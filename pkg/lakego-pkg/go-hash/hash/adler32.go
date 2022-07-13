package hash

import (
    "strconv"
    "hash/adler32"
)

// Adler32
func Adler32(s string) string {
    data := []byte(s)

    res := adler32.Checksum(data)

    return strconv.FormatInt(int64(res), 16)
}

// Adler32
func (this Hash) Adler32() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Adler32(newData), nil
    })
}
