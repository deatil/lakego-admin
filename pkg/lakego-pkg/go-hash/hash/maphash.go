package hash

import (
    "strconv"
    "hash/maphash"
)

// Maphash
func Maphash(data string) string {
    h := &maphash.Hash{}
    h.WriteString(data)

    res := h.Sum64()

    return strconv.FormatInt(int64(res), 16)
}

// Maphash
func (this Hash) Maphash() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Maphash(newData), nil
    })
}
