package hash

import (
    "hash"
    "encoding/hex"
    "encoding/base64"
)

// 默认
var defaultHash Hash

func init() {
    defaultHash = New()
}

// 构造函数
func New() Hash {
    return Hash{}
}

/**
 * hash
 *
 * @create 2022-3-27
 * @author deatil
 */
type Hash struct {
    // 数据
    data []byte

    // hash 接口
    hash hash.Hash

    // 错误
    Error error
}

// Base64 编码
func (this Hash) Base64Encode(src []byte) string {
    return base64.StdEncoding.EncodeToString(src)
}

// Base64 解码
func (this Hash) Base64Decode(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

// Hex 编码
func (this Hash) HexEncode(src []byte) string {
    return hex.EncodeToString(src)
}

// Hex 解码
func (this Hash) HexDecode(s string) ([]byte, error) {
    return hex.DecodeString(s)
}

// 默认方式
func (this Hash) MakeHash(f func() hash.Hash) Hash {
    this.hash = f()

    return this
}

// 自定义方法
func (this Hash) FuncHash(f func([]byte) ([]byte, error)) Hash {
    this.data, this.Error = f(this.data)

    return this
}
