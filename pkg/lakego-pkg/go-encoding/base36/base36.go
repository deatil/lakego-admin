package base36

import (
    "github.com/deatil/go-encoding/baseenc"
)

// encodeStd is the standard base36 encoding alphabet
const encodeStd = "0123456789abcdefghijklmnopqrstuvwxyz"

// StdEncoding is the default encoding enc.
var StdEncoding = NewEncoding(encodeStd)

/*
 * Encodings
 */

// NewEncoding returns a new Encoding defined by the given alphabet, which must
// be a 36-byte string that does not contain CR or LF ('\r', '\n').
func NewEncoding(encoder string) *baseenc.Encoding {
    return baseenc.NewEncoding("base36", 36, encoder)
}
