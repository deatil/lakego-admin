package hash

import (
    "github.com/tjfoc/gmsm/sm3"
)

// 国密 sm3 签名
func (this Hash) SM3() Hash {
    h := sm3.New()
    h.Write(this.data)

    this.data = h.Sum(nil)

    return this
}

// NewSM3
func (this Hash) NewSM3() Hash {
    this.hash = sm3.New()

    return this
}
