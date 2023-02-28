package dh

import (
    cryptobin_dh "github.com/deatil/go-cryptobin/dh/dh"
)

// 构造函数
func NewDh() Dh {
    group, _ := cryptobin_dh.GetMODGroup(cryptobin_dh.P2048)

    return Dh{
        group: group,
        Errors: make([]error, 0),
    }
}

// 构造函数
func New() Dh {
    return NewDh()
}
