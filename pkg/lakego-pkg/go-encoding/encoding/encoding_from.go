package encoding

import (
    "bytes"
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

// Gob
func (this Encoding) ForGob(data interface{}) Encoding {
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
func (this Encoding) ForXML(data interface{}) Encoding {
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
func (this Encoding) ForJSON(data interface{}) Encoding {
    this.data, this.Error = json.Marshal(data)

    return this
}

// Binary
func (this Encoding) ForBinary(data interface{}) Encoding {
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
func (this Encoding) ForAsn1(data interface{}, params ...string) Encoding {
    if len(params) > 0 {
        this.data, this.Error = asn1.MarshalWithParams(data, params[0])
    } else {
        this.data, this.Error = asn1.Marshal(data)
    }

    return this
}
