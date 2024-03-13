package hash

import (
    "github.com/deatil/go-hash/jh"
)

// 国密 jh 签名
func (this Hash) JH() Hash {
    h := jh.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewJH
func (this Hash) NewJH() Hash {
    this.hash = jh.New()

    return this
}
