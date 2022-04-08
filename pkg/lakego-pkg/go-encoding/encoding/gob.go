package encoding

import (
    "bytes"
    "encoding/gob"
)

// Gob 编码
func GobEncode(src interface{}) (string, error) {
    buf := bytes.NewBuffer(nil)

    enc := gob.NewEncoder(buf)
    err := enc.Encode(src)
    if err != nil {
        return "", err
    }

    return buf.String(), nil
}

// Gob 解码
func GobDecode(src string, dst interface{}) error {
    buf := bytes.NewBuffer([]byte(src))
    dec := gob.NewDecoder(buf)
    return dec.Decode(dst)
}
