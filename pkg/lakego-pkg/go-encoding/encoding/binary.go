package encoding

import (
    "bytes"
    "encoding/binary"
)

// Binary 编码
func BinaryEncode(src any) (string, error) {
    buf := bytes.NewBuffer(nil)

    err := binary.Write(buf, binary.LittleEndian, src)
    if err != nil {
        return "", err
    }

    return buf.String(), nil
}

// Binary 解码
func BinaryDecode(src string, dst any) error {
    buf := bytes.NewBuffer([]byte(src))

    return binary.Read(buf, binary.LittleEndian, dst)
}

// ====================

// Binary
func (this Encoding) ForBinary(data any) Encoding {
    buf := bytes.NewBuffer(nil)

    err := binary.Write(buf, binary.LittleEndian, data)
    if err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Binary
func ForBinary(data any) Encoding {
    return defaultEncode.ForBinary(data)
}

// Binary 编码输出
func (this Encoding) BinaryTo(dst any) error {
    buf := bytes.NewBuffer(this.data)

    return binary.Read(buf, binary.LittleEndian, dst)
}
