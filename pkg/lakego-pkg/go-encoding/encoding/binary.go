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
