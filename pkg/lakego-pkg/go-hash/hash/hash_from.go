package hash

import (
    "io"
    "bytes"
)

// 字节
func (this Hash) FromBytes(data []byte) Hash {
    this.data = data

    return this
}

// 字节
func FromBytes(data []byte) Hash {
    return defaultHash.FromBytes(data)
}

// 字符
func (this Hash) FromString(data string) Hash {
    this.data = []byte(data)

    return this
}

// 字符
func FromString(data string) Hash {
    return defaultHash.FromString(data)
}

// FromBase64String
func (this Hash) FromBase64String(data string) Hash {
    this.data, this.Error = this.Base64Decode(data)

    return this
}

// FromBase64String
func FromBase64String(data string) Hash {
    return defaultHash.FromBase64String(data)
}

// FromHexString
func (this Hash) FromHexString(data string) Hash {
    this.data, this.Error = this.HexDecode(data)

    return this
}

// FromHexString
func FromHexString(data string) Hash {
    return defaultHash.FromHexString(data)
}

// FromReader
func (this Hash) FromReader(reader io.Reader) Hash {
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
func FromReader(reader io.Reader) Hash {
    return defaultHash.FromReader(reader)
}
