package util

import (
    "time"
    "sort"
    "strconv"
    "strings"
    "math/rand"
)

// 将Map的键值对，按字典顺序拼接成字符串
func SortKVPairs(m map[string]string) string {
    size := len(m)
    if size == 0 {
        return ""
    }
    keys := make([]string, size)
    idx := 0
    for k := range m {
        keys[idx] = k
        idx++
    }

    sort.Strings(keys)
    pairs := make([]string, size)
    for i, key := range keys {
        pairs[i] = key + "=" + m[key]
    }

    return strings.Join(pairs, "&")
}

// 随机字符串
func RandomStr(n int) string {
    var r = rand.New(rand.NewSource(time.Now().UnixNano()))
    const pattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"

    salt := make([]byte, 0, n)
    l := len(pattern)

    for i := 0; i < n; i++ {
        p := r.Intn(l)
        salt = append(salt, pattern[p])
    }

    return string(salt)
}

// 字符串转int64
func StringToInt64(str string) (int64, error) {
    if str == "" {
        return 0, nil
    }
    valInt, err := strconv.Atoi(str)
    if err != nil {
        return 0, err
    }

    return int64(valInt), nil
}

