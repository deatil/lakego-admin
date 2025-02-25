package encoding

import (
    "bytes"
    "strings"
    "encoding/hex"
    "encoding/base32"
    "encoding/base64"
)

// StdEncoding
var StdEncoding = New()

/**
 * Encoding
 *
 * @create 2022-4-17
 * @author deatil
 */
type Encoding struct{}

// New Encoding
func New() *Encoding {
    return &Encoding{}
}

// Base32 Encode
func (this *Encoding) Base32Encode(src []byte) string {
    return base32.StdEncoding.EncodeToString(src)
}

// Base32 Encode
func Base32Encode(src []byte) string {
    return StdEncoding.Base32Encode(src)
}

// Base32 Decode
func (this *Encoding) Base32Decode(s string) ([]byte, error) {
    return base32.StdEncoding.DecodeString(s)
}

// Base32 Decode
func Base32Decode(s string) ([]byte, error) {
    return StdEncoding.Base32Decode(s)
}

// Base64 Encode
func (this *Encoding) Base64Encode(src []byte) string {
    return base64.StdEncoding.EncodeToString(src)
}

// Base64 Encode
func Base64Encode(src []byte) string {
    return StdEncoding.Base64Encode(src)
}

// Base64 Decode
func (this *Encoding) Base64Decode(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

// Base64 Decode
func Base64Decode(s string) ([]byte, error) {
    return StdEncoding.Base64Decode(s)
}

// Hex Encode
func (this *Encoding) HexEncode(src []byte) string {
    return hex.EncodeToString(src)
}

// Hex Encode
func HexEncode(src []byte) string {
    return StdEncoding.HexEncode(src)
}

// Hex Decode
func (this *Encoding) HexDecode(s string) ([]byte, error) {
    return hex.DecodeString(s)
}

// Hex Decode
func HexDecode(s string) ([]byte, error) {
    return StdEncoding.HexDecode(s)
}

// Hex Padding
func (this *Encoding) HexPadding(text string, size int) string {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        return strings.Repeat("0", size-n) + text
    }

    return text[n-size:]
}

// Hex Padding
func HexPadding(text string, size int) string {
    return StdEncoding.HexPadding(text, size)
}

// Bytes Padding
func (this *Encoding) BytesPadding(text []byte, size int) []byte {
    if size < 1 {
        return text
    }

    n := len(text)

    if n == size {
        return text
    }

    if n < size {
        r := bytes.Repeat([]byte{0x00}, size - n)
        return append(r, text...)
    }

    return text[n-size:]
}

// Bytes Padding
func BytesPadding(text []byte, size int) []byte {
    return StdEncoding.BytesPadding(text, size)
}
