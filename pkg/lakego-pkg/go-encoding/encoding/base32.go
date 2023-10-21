package encoding

import (
    "encoding/base32"
)

var (
    // 自定义编码表
    // newStr := NewBase32Encoding(encoder string).WithPadding(NoPadding).EncodeToString(src []byte)
    // newStr, err := NewBase32Encoding(encoder string).WithPadding(NoPadding).DecodeString(src string)
    NewBase32Encoding = base32.NewEncoding
)

// 解码 Base32
func (this Encoding) Base32Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base32.StdEncoding.DecodeString(data)

    return this
}

// 编码 Base32
func (this Encoding) Base32Encode() Encoding {
    data := base32.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ===========

// 解码 Base32， 不补位
func (this Encoding) Base32RawDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(data)

    return this
}

// 编码 Base32， 不补位
func (this Encoding) Base32RawEncode() Encoding {
    data := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ===========

// 解码 Base32Hex
func (this Encoding) Base32HexDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = base32.HexEncoding.DecodeString(data)

    return this
}

// 编码 Base32Hex
func (this Encoding) Base32HexEncode() Encoding {
    data := base32.HexEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ===========

// 解码 Base32Hex， 不补位
func (this Encoding) Base32RawHexDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(data)

    return this
}

// 编码 Base32Hex， 不补位
func (this Encoding) Base32RawHexEncode() Encoding {
    data := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ===========

// 解码 Base32Encoder
func (this Encoding) Base32DecodeWithEncoder(encoder string) Encoding {
    data := string(this.data)
    this.data, this.Error = base32.NewEncoding(encoder).DecodeString(data)

    return this
}

// 编码 Base32Encoder
func (this Encoding) Base32EncodeWithEncoder(encoder string) Encoding {
    data := base32.NewEncoding(encoder).EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ===========

// 解码 Base32Encoder， 不补位
func (this Encoding) Base32RawDecodeWithEncoder(encoder string) Encoding {
    data := string(this.data)
    this.data, this.Error = base32.NewEncoding(encoder).WithPadding(base32.NoPadding).DecodeString(data)

    return this
}

// 编码 Base32Encoder， 不补位
func (this Encoding) Base32RawEncodeWithEncoder(encoder string) Encoding {
    data := base32.NewEncoding(encoder).WithPadding(base32.NoPadding).EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
