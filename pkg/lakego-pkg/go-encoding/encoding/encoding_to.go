package encoding

import (
    "io"
    "bytes"
)

// 输出原始字符
func (this Encoding) String() string {
    return this.ToString()
}

// 输出字节
func (this Encoding) ToBytes() []byte {
    return this.data
}

// 输出字符
func (this Encoding) ToString() string {
    return string(this.data)
}

// 输出 io.Reader
func (this Encoding) ToReader() io.Reader {
    return bytes.NewBuffer(this.data)
}
