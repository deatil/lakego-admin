package hash

import (
    "io"
    "bytes"
)

// 输出字符
func (this Hash) String() string {
    return this.ToString()
}

// 输出字节
func (this Hash) ToBytes() []byte {
    return this.data
}

// 输出字符
func (this Hash) ToString() string {
    return string(this.data)
}

// 输出Base64
func (this Hash) ToBase64String() string {
    return this.Base64Encode(this.data)
}

// 输出Hex
func (this Hash) ToHexString() string {
    return this.HexEncode(this.data)
}

// 输出 io.Reader
func (this Hash) ToReader() io.Reader {
    return bytes.NewBuffer(this.data)
}
