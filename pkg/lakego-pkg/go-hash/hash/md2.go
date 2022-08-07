package hash

import (
    "encoding/hex"

    "github.com/deatil/go-hash/md2"
)

// md2 签名
func MD2(data string) string {
    m := md2.New()
    m.Write([]byte(data))

    return hex.EncodeToString(m.Sum(nil))
}

// md2 签名
func (this Hash) MD2() Hash {
    return this.UseHash(md2.New)
}
