package encoding

import (
    "bytes"
    "encoding/gob"
)

// Gob
func (this Encoding) GobEncode(data any) Encoding {
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

// Gob 编码输出
func (this Encoding) GobDecode(dst any) Encoding {
    buf := bytes.NewBuffer(this.data)
    dec := gob.NewDecoder(buf)

    this.Error = dec.Decode(dst)

    return this
}
