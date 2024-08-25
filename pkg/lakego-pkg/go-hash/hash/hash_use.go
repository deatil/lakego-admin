package hash

import (
    "fmt"
    "hash"
    "strconv"
)

// Type Mode
var TypeMode = NewTypeSet[Mode, string](maxMode)

// Mode type
type Mode uint

func (this Mode) String() string {
    switch this {
        default:
            if TypeMode.Names().Has(this) {
                return (TypeMode.Names().Get(this))()
            }

            return "unknown mode value " + strconv.Itoa(int(this))
    }
}

const (
    unknown Mode = 1 + iota
    maxMode
)

// 接口
type IHash interface {
    // Sum [输入内容, 其他配置]
    Sum(data []byte, cfg ...any) ([]byte, error)

    // New
    New(cfg ...any) (hash.Hash, error)
}

// 使用
var UseHash = NewDataSet[Mode, IHash]()

// 获取方式
func getHash(name Mode) (IHash, error) {
    if !UseHash.Has(name) {
        err := fmt.Errorf("Hash: Hash type [%s] is error.", name)
        return nil, err
    }

    newHash := UseHash.Get(name)

    return newHash(), nil
}

// Sum
func (this Hash) SumBy(name Mode, cfg ...any) Hash {
    newHash, err := getHash(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newHash.Sum(this.data, cfg...)

    return this
}

// New
func (this Hash) NewBy(name Mode, cfg ...any) Hash {
    newHash, err := getHash(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.hash, this.Error = newHash.New(cfg...)

    return this
}
