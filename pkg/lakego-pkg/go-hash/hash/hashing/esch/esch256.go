package esch

import (
    go_hash "hash"

    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-hash/esch"
)

type ESCH256Hash struct {}

// 编码
func (this ESCH256Hash) Sum(data []byte, cfg ...any) ([]byte, error) {
    sum := esch.Sum256(data)

    return sum[:], nil
}

// 解码
func (this ESCH256Hash) New(cfg ...any) (go_hash.Hash, error) {
    return esch.New256(), nil
}

var ESCH256 = hash.TypeMode.Generate()

func init() {
    hash.TypeMode.Names().Add(ESCH256, func() string {
        return "ESCH256"
    })

    hash.UseHash.Add(ESCH256, func() hash.IHash {
        return ESCH256Hash{}
    })
}
