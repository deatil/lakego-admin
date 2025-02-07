package encoding

import (
    "bytes"
    "encoding/binary"
)

// Binary Little Endian Encode
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

// Binary Little Endian Decode
func (this Encoding) BinaryLittleEndianDecode(dst any) Encoding {
    buf := bytes.NewBuffer(this.data)

    this.Error = binary.Read(buf, binary.LittleEndian, dst)

    return this
}

// ====================

// Binary Big Endian Encode
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

// Binary Big Endian Decode
func (this Encoding) BinaryBigEndianDecode(dst any) Encoding {
    buf := bytes.NewBuffer(this.data)

    this.Error = binary.Read(buf, binary.BigEndian, dst)

    return this
}
