package encoding

import (
    "bytes"
)

// 字节
func (this Encoding) FromBytes(data []byte) Encoding {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Encoding {
    return defaultEncode.FromBytes(data)
}

// 字符
func (this Encoding) FromString(data string) Encoding {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Encoding {
    return defaultEncode.FromString(data)
}

// BytesBuffer
func (this Encoding) FromBytesBuffer(data *bytes.Buffer) Encoding {
    this.data = data.Bytes()

    return this
}

// Hex
func FromBytesBuffer(data *bytes.Buffer) Encoding {
    return defaultEncode.FromBytesBuffer(data)
}
