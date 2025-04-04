package encoding

import (
    "bytes"
    "encoding/xml"
)

// Xml Decode
func (this Encoding) XmlDecode(dst any) Encoding {
    buf := bytes.NewBuffer(this.data)
    dec := xml.NewDecoder(buf)

    this.Error = dec.Decode(dst)

    return this
}

// Xml Encode
func (this Encoding) XmlEncode(data any) Encoding {
    buf := bytes.NewBuffer(nil)

    enc := xml.NewEncoder(buf)
    err := enc.Encode(data)
    if err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}
