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
