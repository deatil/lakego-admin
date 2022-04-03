package hash

import (
    "hash"
)

// 默认方式
func (this Hash) MakeHash(sha func() hash.Hash, slices ...[]byte) []byte {
    f := sha()
    for _, slice := range slices {
        f.Write(slice)
    }

    return f.Sum(nil)
}

// 使用 Hash 方法
func (this Hash) UseHash(sha func() hash.Hash) Hash {
    data := this.MakeHash(sha, this.data...)

    this.hashedData = this.HexEncode(data)

    return this
}

// 自定义方法
func (this Hash) FuncHash(f func(...[]byte) (string, error)) Hash {
    this.hashedData, this.Error = f(this.data...)

    return this
}
