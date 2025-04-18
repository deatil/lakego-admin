package encoding

import (
    "strings"
    "encoding/base64"
)

var (
    // newStr := NewBase64Encoding(encoder string).WithPadding(NoPadding).EncodeToString(src []byte)
    // newStr, err := NewBase64Encoding(encoder string).WithPadding(NoPadding).DecodeString(src string)
    NewBase64Encoding = base64.NewEncoding
)

// Base64 Decode
func (this Encoding) Base64Decode() Encoding {
    data := string(this.data)
    this.data, this.Error = base64.StdEncoding.DecodeString(data)

    return this
}

// Base64 Encode
func (this Encoding) Base64Encode() Encoding {
    data := base64.StdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ====================

// Base64 URL Decode
func (this Encoding) Base64URLDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = base64.URLEncoding.DecodeString(data)

    return this
}

// Base64 URL Encode
func (this Encoding) Base64URLEncode() Encoding {
    data := base64.URLEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ====================

// Base64 Raw Decode
func (this Encoding) Base64RawDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = base64.RawStdEncoding.DecodeString(data)

    return this
}

// Base64 Raw Encode
func (this Encoding) Base64RawEncode() Encoding {
    data := base64.RawStdEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ====================

// Base64RawURL Decode
func (this Encoding) Base64RawURLDecode() Encoding {
    data := string(this.data)
    this.data, this.Error = base64.RawURLEncoding.DecodeString(data)

    return this
}

// Base64RawURL Encode
func (this Encoding) Base64RawURLEncode() Encoding {
    data := base64.RawURLEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ====================

// Base64Segment Decode
func (this Encoding) Base64SegmentDecode(paddingAllowed ...bool) Encoding {
    data := string(this.data)

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

// Base64Segment Encode
func (this Encoding) Base64SegmentEncode() Encoding {
    data := base64.RawURLEncoding.EncodeToString(this.data)
    this.data = []byte(data)

    return this
}

// ====================

// Base64 Decode With Encoder
func (this Encoding) Base64DecodeWithEncoder(encoder string) Encoding {
    data := string(this.data)
    this.data, this.Error = base64.NewEncoding(encoder).DecodeString(data)

    return this
}

// Base64 Encode With Encoder
func (this Encoding) Base64EncodeWithEncoder(encoder string) Encoding {
    data := base64.NewEncoding(encoder).EncodeToString(this.data)
    this.data = []byte(data)

    return this
}
