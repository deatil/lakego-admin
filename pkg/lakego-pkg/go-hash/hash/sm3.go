package hash

import (
    "encoding/hex"

    "github.com/tjfoc/gmsm/sm3"
)

// 国密 sm3 签名
func SM3(data string) string {
    m := sm3.New()
    m.Write([]byte(data))

    return hex.EncodeToString(m.Sum(nil))
}

// 国密 sm3 签名
func (this Hash) SM3() Hash {
    return this.UseHash(sm3.New)
}
