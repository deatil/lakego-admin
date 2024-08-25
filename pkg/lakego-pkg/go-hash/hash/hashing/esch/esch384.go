package esch

import (
    go_hash "hash"

    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-hash/esch"
)

type ESCH384Hash struct {}

// 编码
func (this ESCH384Hash) Sum(data []byte, cfg ...any) ([]byte, error) {
    sum := esch.Sum384(data)

    return sum[:], nil
}

// 解码
func (this ESCH384Hash) New(cfg ...any) (go_hash.Hash, error) {
    return esch.New384(), nil
}

var ESCH384 = hash.TypeMode.Generate()

func init() {
    hash.TypeMode.Names().Add(ESCH384, func() string {
        return "ESCH384"
    })

    hash.UseHash.Add(ESCH384, func() hash.IHash {
        return ESCH384Hash{}
    })
}
