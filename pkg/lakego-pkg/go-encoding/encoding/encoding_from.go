package encoding

import (
    "bytes"
    "errors"
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

    "github.com/deatil/go-encoding/morse"
    "github.com/deatil/go-encoding/basex"
    "github.com/deatil/go-encoding/base45"
    "github.com/deatil/go-encoding/base62"
    "github.com/deatil/go-encoding/base91"
    "github.com/deatil/go-encoding/base100"
)

// 字节
func (this Encoding) FromBytes(data []byte) Encoding {
    this.data = data

    return this
}

// 字符
func (this Encoding) FromString(data string) Encoding {
    this.data = []byte(data)

    return this
}

// Base32
func (this Encoding) FromBase32String(data string) Encoding {
    this.data, this.Error = base32.StdEncoding.DecodeString(data)

    return this
}

// Base32Hex
func (this Encoding) FromBase32HexString(data string) Encoding {
    this.data, this.Error = base32.HexEncoding.DecodeString(data)

    return this
}

// FromBase32EncoderString
func (this Encoding) FromBase32EncoderString(data string, encoder string) Encoding {
    this.data, this.Error = base32.NewEncoding(encoder).DecodeString(data)

    return this
}

// Base45
func (this Encoding) FromBase45String(data string) Encoding {
    decoded, err := base45.Decode(data)

    this.data = []byte(decoded)
    this.Error = err

    return this
}

// Base58
func (this Encoding) FromBase58String(data string) Encoding {
    data = Base58Decode(data)

    this.data = []byte(data)

    return this
}

// Base64
func (this Encoding) FromBase64String(data string) Encoding {
    this.data, this.Error = base64.StdEncoding.DecodeString(data)

    return this
}

// Base64URL
func (this Encoding) FromBase64URLString(data string) Encoding {
    this.data, this.Error = base64.URLEncoding.DecodeString(data)

    return this
}

// Base64Raw
func (this Encoding) FromBase64RawString(data string) Encoding {
    this.data, this.Error = base64.RawStdEncoding.DecodeString(data)

    return this
}

// Base64RawURL
func (this Encoding) FromBase64RawURLString(data string) Encoding {
    this.data, this.Error = base64.RawURLEncoding.DecodeString(data)

    return this
}

// Base64Segment
func (this Encoding) FromBase64SegmentString(data string, paddingAllowed ...bool) Encoding {
    if len(paddingAllowed) > 0 && paddingAllowed[0] {
        if l := len(data) % 4; l > 0 {
            data += strings.Repeat("=", 4-l)
        }

        this.data, this.Error = base64.URLEncoding.DecodeString(data)

        return this
    }

    this.data, this.Error = base64.RawURLEncoding.DecodeString(data)

    return this
}

// FromBase64EncoderString
func (this Encoding) FromBase64EncoderString(data string, encoder string) Encoding {
    this.data, this.Error = base64.NewEncoding(encoder).DecodeString(data)

    return this
}

// Base85
func (this Encoding) FromBase85String(data string) Encoding {
    src := []byte(data)

    decodedText := make([]byte, len(src))
    decoded, _, err := ascii85.Decode(decodedText, src, true)
    if err != nil {
        this.Error = err
        return this
    }

    decodedText = decodedText[:decoded]

    this.data = bytes.Trim(decodedText, "\x00")

    return this
}

// Base2
func (this Encoding) FromBase2String(data string) Encoding {
    this.data, this.Error = basex.Base2Encoding.Decode(data)

    return this
}

// Base16
func (this Encoding) FromBase16String(data string) Encoding {
    this.data, this.Error = basex.Base16Encoding.Decode(data)

    return this
}

// Basex62
func (this Encoding) FromBasex62String(data string) Encoding {
    this.data, this.Error = basex.Base62Encoding.Decode(data)

    return this
}

// FromBasexEncoderString
func (this Encoding) FromBasexEncoderString(data string, encoder string) Encoding {
    this.data, this.Error = basex.NewEncoding(encoder).Decode(data)

    return this
}

// Base62
func (this Encoding) FromBase62String(data string) Encoding {
    this.data, this.Error = base62.StdEncoding.DecodeString(data)

    return this
}

// Base91
func (this Encoding) FromBase91String(data string) Encoding {
    this.data, this.Error = base91.StdEncoding.DecodeString(data)

    return this
}

// Base100
func (this Encoding) FromBase100String(data string) Encoding {
    this.data, this.Error = base100.Decode(data)

    return this
}

// MorseITU
func (this Encoding) FromMorseITUString(data string) Encoding {
    data, err := morse.DecodeITU(data)

    this.data = []byte(data)
    this.Error = err

    return this
}

// Hex
func (this Encoding) FromHexString(data string) Encoding {
    this.data, this.Error = hex.DecodeString(data)

    return this
}

// BytesBuffer
func (this Encoding) FromBytesBuffer(data *bytes.Buffer) Encoding {
    this.data = data.Bytes()

    return this
}

// 给定类型数据格式化为string类型数据
// bitSize 限制长度
// ParseBool()、ParseFloat()、ParseInt()、ParseUint()。
// FormatBool()、FormatInt()、FormatUint()、FormatFloat()、
func (this Encoding) FromConvert(input any, base int, bitSize ...int) Encoding {
    newBitSize := 0
    if len(bitSize) > 0 {
        newBitSize = bitSize[0]
    }

    var number int64
    var err error

    switch input.(type) {
        case int:
            number = int64(input.(int))
        case int8:
            number = int64(input.(int8))
        case int16:
            number = int64(input.(int16))
        case int32:
            number = int64(input.(int32))
        case int64:
            number = input.(int64)
        case string:
            number, err = strconv.ParseInt(input.(string), base, newBitSize)
            if err != nil {
                this.Error = err
                return this
            }
        default:
            this.Error = errors.New("数据输入格式错误")
            return this
    }

    // 转为10进制字符
    data := strconv.FormatInt(number, 10)

    this.data = []byte(data)

    return this
}

// 二进制
func (this Encoding) FromConvertBin(data string) Encoding {
    return this.FromConvert(data, 2)
}

// 八进制
func (this Encoding) FromConvertOct(data string) Encoding {
    return this.FromConvert(data, 8)
}

// 十进制
func (this Encoding) FromConvertDec(data int64) Encoding {
    return this.FromConvert(data, 10)
}

// 十进制字符
func (this Encoding) FromConvertDecString(data string) Encoding {
    return this.FromConvert(data, 10)
}

// 十六进制
func (this Encoding) FromConvertHex(data string) Encoding {
    return this.FromConvert(data, 16)
}

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

// JSON
func (this Encoding) ForJSON(data any) Encoding {
    this.data, this.Error = json.Marshal(data)

    return this
}

// Binary
func (this Encoding) ForBinary(data any) Encoding {
    buf := bytes.NewBuffer(nil)

    err := binary.Write(buf, binary.LittleEndian, data)
    if err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Csv
func (this Encoding) ForCsv(data [][]string) Encoding {
    buf := bytes.NewBuffer(nil)

    w := csv.NewWriter(buf)
    w.WriteAll(data)

    if err := w.Error(); err != nil {
        this.Error = err
        return this
    }

    this.data = buf.Bytes()

    return this
}

// Asn1
func (this Encoding) ForAsn1(data any, params ...string) Encoding {
    if len(params) > 0 {
        this.data, this.Error = asn1.MarshalWithParams(data, params[0])
    } else {
        this.data, this.Error = asn1.Marshal(data)
    }

    return this
}

// 序列化
func (this Encoding) ForSerialize(data any) Encoding {
    this.data, this.Error = Serialize(data)

    return this
}
