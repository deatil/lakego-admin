package encoding

import (
    "io"
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

// FromReader
func (this Encoding) FromReader(reader io.Reader) Encoding {
    buf := bytes.NewBuffer(nil)

    // 保存
    if _, err := io.Copy(buf, reader); err != nil {
        this.Error = err

        return this
    }

    this.data = buf.Bytes()

    return this
}

// FromReader
func FromReader(reader io.Reader) Encoding {
    return defaultEncode.FromReader(reader)
}
