package encoding

import (
    "bytes"
    "strings"
    "encoding/csv"
    "encoding/gob"
    "encoding/xml"
    "encoding/hex"
    "encoding/json"
    "encoding/asn1"
    "encoding/base32"
    "encoding/base64"
    "encoding/ascii85"
    "encoding/binary"
)

// 输出原始字符
func (this Encoding) String() string {
    return string(this.data)
}

// 输出字节
func (this Encoding) ToBytes() []byte {
    return this.data
}

// 输出字符
func (this Encoding) ToString() string {
    return string(this.data)
}

// 输出Base64
func (this Encoding) ToBase32String() string {
    return base32.StdEncoding.EncodeToString(this.data)
}

// 输出Base64
func (this Encoding) ToBase58String() string {
    return Base58Encode(string(this.data))
}

// 输出Base64
func (this Encoding) ToBase64String() string {
    return base64.StdEncoding.EncodeToString(this.data)
}

// 输出Base85
func (this Encoding) ToBase85String() string {
    text := this.data

    dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
    ascii85.Encode(dest, text)

    return string(dest)
}

// 输出Hex
func (this Encoding) ToHexString() string {
    return hex.EncodeToString(this.data)
}

// 输出 BytesBuffer
func (this Encoding) ToBytesBuffer() *bytes.Buffer {
    return bytes.NewBuffer(this.data)
}

// Gob 编码输出
func (this Encoding) GobTo(dst interface{}) error {
    buf := bytes.NewBuffer(this.data)
    dec := gob.NewDecoder(buf)

    return dec.Decode(dst)
}

// Xml 编码输出
func (this Encoding) XMLTo(dst interface{}) error {
    buf := bytes.NewBuffer(this.data)
    dec := xml.NewDecoder(buf)

    return dec.Decode(dst)
}

// JSON 编码输出
func (this Encoding) JSONTo(dst interface{}) error {
    return json.Unmarshal(this.data, dst)
}

// Binary 编码输出
func (this Encoding) BinaryTo(dst interface{}) error {
    buf := bytes.NewBuffer(this.data)

    return binary.Read(buf, binary.LittleEndian, dst)
}

// Csv 编码输出
func (this Encoding) CsvTo(opts ...rune) ([][]string, error) {
    buf := strings.NewReader(string(this.data))
    r := csv.NewReader(buf)

    if len(opts) > 0 {
        // ';'
        r.Comma = opts[0]
    }

    if len(opts) > 1 {
        // '#'
        r.Comment = opts[1]
    }

    return r.ReadAll()
}

// Asn1 编码输出
func (this Encoding) Asn1To(val interface{}, params ...string) ([]byte, error) {
    if len(params) > 0 {
        return asn1.UnmarshalWithParams(this.data, val, params[0])
    } else {
        return asn1.Unmarshal(this.data, val)
    }
}
