package hash

import (
    "strconv"
    "hash/fnv"
    "encoding/hex"
)

// Fnv32
func Fnv32(data string) string {
    m := fnv.New32()
    m.Write([]byte(data))

    res := m.Sum32()

    return strconv.FormatInt(int64(res), 16)
}

// Fnv32
func (this Hash) Fnv32() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Fnv32(newData), nil
    })
}

// =======================

// Fnv32a
func Fnv32a(data string) string {
    m := fnv.New32a()
    m.Write([]byte(data))

    res := m.Sum32()

    return strconv.FormatInt(int64(res), 16)
}

// Fnv32a
func (this Hash) Fnv32a() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Fnv32a(newData), nil
    })
}

// =======================

// Fnv64
func Fnv64(data string) string {
    m := fnv.New64()
    m.Write([]byte(data))

    res := m.Sum64()

    return strconv.FormatInt(int64(res), 16)
}

// Fnv64
func (this Hash) Fnv64() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Fnv64(newData), nil
    })
}

// =======================

// Fnv64a
func Fnv64a(data string) string {
    m := fnv.New64a()
    m.Write([]byte(data))

    res := m.Sum64()

    return strconv.FormatInt(int64(res), 16)
}

// Fnv64a
func (this Hash) Fnv64a() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Fnv64a(newData), nil
    })
}

// =======================

// Fnv128
func Fnv128(data string) string {
    m := fnv.New128()
    m.Write([]byte(data))

    return hex.EncodeToString(m.Sum(nil))
}

// Fnv128
func (this Hash) Fnv128() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Fnv128(newData), nil
    })
}

// =======================

// Fnv128a
func Fnv128a(data string) string {
    m := fnv.New128a()
    m.Write([]byte(data))

    return hex.EncodeToString(m.Sum(nil))
}

// Fnv128a
func (this Hash) Fnv128a() Hash {
    return this.FuncHash(func(data ...[]byte) (string, error) {
        newData := ""
        for _, v := range data {
            newData += string(v)
        }

        return Fnv128a(newData), nil
    })
}
