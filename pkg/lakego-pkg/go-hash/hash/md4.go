package hash

import (
    "encoding/hex"
    "golang.org/x/crypto/md4"
)

// MD4 哈希值
func MD4(data string) string {
    h := md4.New()
    h.Write([]byte(data))
    return hex.EncodeToString(h.Sum(nil))
}

// MD4 哈希值
func (this Hash) MD4() Hash {
    return this.UseHash(md4.New)
}
