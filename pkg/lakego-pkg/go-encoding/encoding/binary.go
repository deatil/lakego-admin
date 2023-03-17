package encoding

import (
    "bytes"
    "encoding/binary"
)

// Binary 小端编码
func (this Encoding) BinaryLittleEndianEncode(data any) Encoding {
    buf := bytes.NewBuffer(nil)

    err := binary.Write(buf, binary.LittleEndian, data)
    if err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Binary 小端解码
func (this Encoding) BinaryLittleEndianDecode(dst any) Encoding {
    buf := bytes.NewBuffer(this.data)

    this.Error = binary.Read(buf, binary.LittleEndian, dst)

    return this
}

// ====================

// Binary 大端编码
func (this Encoding) BinaryBigEndianEncode(data any) Encoding {
    buf := bytes.NewBuffer(nil)

    err := binary.Write(buf, binary.BigEndian, data)
    if err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Binary 大端加码
func (this Encoding) BinaryBigEndianDecode(dst any) Encoding {
    buf := bytes.NewBuffer(this.data)

    this.Error = binary.Read(buf, binary.BigEndian, dst)

    return this
}
