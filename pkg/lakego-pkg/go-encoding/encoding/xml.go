package encoding

import (
    "bytes"
    "encoding/xml"
)

// xml 编码
func XmlEncode(src any) (string, error) {
    buf := bytes.NewBuffer(nil)

    enc := xml.NewEncoder(buf)
    err := enc.Encode(src)
    if err != nil {
        return "", err
    }

    return buf.String(), nil
}

// xml 解码
func XmlDecode(src string, dst any) error {
    buf := bytes.NewBuffer([]byte(src))
    dec := xml.NewDecoder(buf)
    return dec.Decode(dst)
}

// ====================

// Xml
func (this Encoding) ForXML(data any) Encoding {
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

// Xml
func ForXML(data any) Encoding {
    return defaultEncode.ForXML(data)
}

// Xml 编码输出
func (this Encoding) XMLTo(dst any) error {
    buf := bytes.NewBuffer(this.data)
    dec := xml.NewDecoder(buf)

    return dec.Decode(dst)
}
