package hash

import (
    "fmt"
    "hash"
)

// 接口
type IHash interface {
    // Sum [输入内容, sum输入值, 其他配置]
    Sum([]byte, []byte, ...map[string]any) ([]byte, error)

    // New
    New(...map[string]any) (hash.Hash, error)
}

// 使用
var UseHash = NewDataSet[string, IHash]()

// 获取方式
func getHash(name string) (IHash, error) {
    if !UseHash.Has(name) {
        err := fmt.Errorf("Hash: Hash type [%s] is error.", name)
        return nil, err
    }

    newHash := UseHash.Get(name)

    return newHash(), nil
}

// Sum
func (this Hash) SumBy(name string, in []byte, cfg ...map[string]any) Hash {
    newHash, err := getHash(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.data, this.Error = newHash.Sum(this.data, in, cfg...)

    return this
}

// New
func (this Hash) NewBy(name string, cfg ...map[string]any) Hash {
    newHash, err := getHash(name)
    if err != nil {
        this.Error = err
        return this
    }

    this.hash, this.Error = newHash.New(cfg...)

    return this
}
