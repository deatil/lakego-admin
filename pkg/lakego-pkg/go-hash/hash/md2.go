package hash

import (
    "github.com/deatil/go-hash/md2"
)

// md2 签名
func (this Hash) MD2() Hash {
    h := md2.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewMD2
func (this Hash) NewMD2() Hash {
    this.hash = md2.New()

    return this
}
