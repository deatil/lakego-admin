package encoding

import (
    "bytes"
    "encoding/gob"
)

// Gob 编码
func GobEncode(src any) (string, error) {
    buf := bytes.NewBuffer(nil)

    enc := gob.NewEncoder(buf)
    err := enc.Encode(src)
    if err != nil {
        return "", err
    }

    return buf.String(), nil
}

// Gob 解码
func GobDecode(src string, dst any) error {
    buf := bytes.NewBuffer([]byte(src))
    dec := gob.NewDecoder(buf)
    return dec.Decode(dst)
}

// ====================

// Gob
func (this Encoding) ForGob(data any) Encoding {
    buf := bytes.NewBuffer(nil)

    enc := gob.NewEncoder(buf)
    err := enc.Encode(data)
    if err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Gob
func ForGob(data any) Encoding {
    return defaultEncode.ForGob(data)
}

// Gob 编码输出
func (this Encoding) GobTo(dst any) error {
    buf := bytes.NewBuffer(this.data)
    dec := gob.NewDecoder(buf)

    return dec.Decode(dst)
}
