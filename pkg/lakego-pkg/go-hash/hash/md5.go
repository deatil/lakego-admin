package hash

import (
    "crypto/md5"
    "encoding/hex"
)

// MD5 哈希值
func MD5(s string) string {
    sum := md5.Sum([]byte(s))
    return hex.EncodeToString(sum[:])
}

// MD5
func (this Hash) MD5() Hash {
    return this.UseHash(md5.New)
}

// MD5 16位哈希值
func MD5_16(s string) string {
    data := MD5(s)
    return data[8:24]
}

// MD5 16位哈希值
func (this Hash) MD5_16() Hash {
    h := this.MD5()
    data := h.hashedData

    h.hashedData = data[8:24]

    return h
}
