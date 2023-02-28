package ecdh

import (
    "crypto/ecdh"
)

// 构造函数
func NewEcdh() Ecdh {
    curve := ecdh.P256()

    return Ecdh{
        curve: curve,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() Ecdh {
    return NewEcdh()
}
