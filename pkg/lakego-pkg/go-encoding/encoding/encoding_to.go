package encoding

import (
    "bytes"
    "strings"
    "strconv"
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

// 输出 Base32
func (this Encoding) ToBase32String() string {
    return base32.StdEncoding.EncodeToString(this.data)
}

// 输出 Base58
func (this Encoding) ToBase58String() string {
    return Base58Encode(string(this.data))
}

// 输出 Base64
func (this Encoding) ToBase64String() string {
    return base64.StdEncoding.EncodeToString(this.data)
}

// 输出 Base64URL
func (this Encoding) ToBase64URLString() string {
    return base64.URLEncoding.EncodeToString(this.data)
}

// 输出 Base64Raw
func (this Encoding) ToBase64RawString() string {
    return base64.RawStdEncoding.EncodeToString(this.data)
}

// 输出 Base64RawURL
func (this Encoding) ToBase64RawURLString() string {
    return base64.RawURLEncoding.EncodeToString(this.data)
}

// 输出 Base64Segment
func (this Encoding) ToBase64SegmentString() string {
    return strings.TrimRight(base64.URLEncoding.EncodeToString(this.data), "=")
}

// 输出 Base85
func (this Encoding) ToBase85String() string {
    text := this.data

    dest := make([]byte, ascii85.MaxEncodedLen(len(text)))
    ascii85.Encode(dest, text)

    return string(dest)
}

// 输出 Hex
func (this Encoding) ToHexString() string {
    return hex.EncodeToString(this.data)
}

// 输出 BytesBuffer
func (this Encoding) ToBytesBuffer() *bytes.Buffer {
    return bytes.NewBuffer(this.data)
}

// 输出进制编码
func (this Encoding) ToConvert(base int) string {
    number, err := strconv.ParseInt(string(this.data), 10, 0)
    if err != nil {
        return ""
    }

    return strconv.FormatInt(number, base)
}

// 输出 二进制
func (this Encoding) ToConvertBin() string {
    return this.ToConvert(2)
}

// 输出 八进制
func (this Encoding) ToConvertOct() string {
    return this.ToConvert(8)
}

// 输出 十进制
func (this Encoding) ToConvertDec() int64 {
    number, err := strconv.ParseInt(string(this.data), 10, 0)
    if err != nil {
        return 0
    }

    return number
}

// 输出 十进制
func (this Encoding) ToConvertDecString() string {
    return this.ToConvert(10)
}

// 输出 十六进制
func (this Encoding) ToConvertHex() string {
    return this.ToConvert(16)
}

// Gob 编码输出
func (this Encoding) GobTo(dst any) error {
    buf := bytes.NewBuffer(this.data)
    dec := gob.NewDecoder(buf)

    return dec.Decode(dst)
}

// Xml 编码输出
func (this Encoding) XMLTo(dst any) error {
    buf := bytes.NewBuffer(this.data)
    dec := xml.NewDecoder(buf)

    return dec.Decode(dst)
}

// JSON 编码输出
func (this Encoding) JSONTo(dst any) error {
    return json.Unmarshal(this.data, dst)
}

// Binary 编码输出
func (this Encoding) BinaryTo(dst any) error {
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
func (this Encoding) Asn1To(val any, params ...string) ([]byte, error) {
    if len(params) > 0 {
        return asn1.UnmarshalWithParams(this.data, val, params[0])
    } else {
        return asn1.Unmarshal(this.data, val)
    }
}
