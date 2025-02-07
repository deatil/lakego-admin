package base92

import (
    "fmt"
)

const (
    // approximation of ceil(log(256)/log(base)).
    // power of two -> speed up DecodeString()
    numerator   = 16
    denominator = 13
)

// encodeStd is the standard base92 encoding alphabet
const encodeStd = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#|;,_~`\""

// StdEncoding is the default encoding enc.
var StdEncoding = NewEncoding(encodeStd)

/*
 * Encodings
 */

// An Encoding is a base 92 encoding/decoding scheme defined by a 92-character alphabet.
type Encoding struct {
    encode    [92]byte
    decodeMap [128]byte
}

// NewEncoding returns a new Encoding defined by the given alphabet, which must
// be a 92-byte string that does not contain CR or LF ('\r', '\n').
func NewEncoding(encoder string) *Encoding {
    if len(encoder) != 92 {
        panic("go-encoding/base92: encoding alphabet is not 92 bytes long")
    }

    for i := 0; i < len(encoder); i++ {
        if encoder[i] == '\n' || encoder[i] == '\r' {
            panic("go-encoding/base92: encoding alphabet contains newline character")
        }
    }

    e := new(Encoding)
    copy(e.encode[:], encoder)

    for i := 0; i < len(e.decodeMap); i++ {
        // 0xff indicates that this entry in the decode map is not in the encoding alphabet.
        e.decodeMap[i] = 0xff
    }

    for i := 0; i < len(encoder); i++ {
        e.decodeMap[encoder[i]] = byte(i)
    }

    return e
}

/*
 * Encoder
 */

// EncodeToString encodes binary bytes into a Base92 string.
func (enc *Encoding) Encode(bin []byte) []byte {
    size := len(bin)

    zcount := 0
    for zcount < size && bin[zcount] == 0 {
        zcount++
    }

    // It is crucial to make this as short as possible, especially for
    // the usual case of bitcoin addrs
    // This is an integer simplification of
    // ceil(log(256)/log(base))
    size = zcount + (size-zcount)*numerator/denominator + 1

    out := make([]byte, size)

    var i, high int
    var carry uint32

    high = size - 1
    for _, b := range bin {
        i = size - 1
        for carry = uint32(b); i > high || carry != 0; i-- {
            carry += 256 * uint32(out[i])
            out[i] = byte(carry % 92)
            carry /= 92
        }

        high = i
    }

    // Determine the additional "zero-gap" in the buffer (aside from zcount)
    for i = zcount; i < size && out[i] == 0; i++ {
    }

    // Now encode the values with actual alphabet in-place
    val := out[i-zcount:]
    size = len(val)
    for i = 0; i < size; i++ {
        out[i] = enc.encode[val[i]]
    }

    return out[:size]
}

// EncodeToString encodes binary bytes into Base92 bytes.
func (enc *Encoding) EncodeToString(bin []byte) string {
    return string(enc.Encode(bin))
}

/*
 * Decoder
 */

// Decode decodes src using the encoding enc.
func (enc *Encoding) Decode(src []byte) ([]byte, error) {
    return enc.DecodeString(string(src))
}

// DecodeString decodes a Base92 string into binary bytes.
func (enc *Encoding) DecodeString(str string) ([]byte, error) {
    if len(str) == 0 {
        return nil, nil
    }

    zero := enc.encode[0]
    strLen := len(str)

    var zcount int
    for i := 0; i < strLen && str[i] == zero; i++ {
        zcount++
    }

    var t, c uint64

    // the 32bit algo stretches the result up to 2 times
    binu := make([]byte, 2*((strLen*denominator/numerator)+1))
    outi := make([]uint32, (strLen+3)/4)

    for _, r := range str {
        if r > 127 {
            return nil, fmt.Errorf("go-encoding/base92: high-bit set on invalid digit")
        }

        if enc.decodeMap[r] == 0xff {
            return nil, fmt.Errorf("go-encoding/base92: invalid digit %q", r)
        }

        c = uint64(enc.decodeMap[r])

        for j := len(outi) - 1; j >= 0; j-- {
            t = uint64(outi[j])*92 + c
            c = t >> 32
            outi[j] = uint32(t & 0xffffffff)
        }
    }

    // initial mask depends on b92sz,
    // on further loops it always starts at 24 bits
    mask := (uint(strLen%4) * 8)
    if mask == 0 {
        mask = 32
    }
    mask -= 8

    outLen := 0
    for j := 0; j < len(outi); j++ {
        // loop relies on uint overflow
        for mask < 32 {
            binu[outLen] = byte(outi[j] >> mask)
            mask -= 8
            outLen++
        }

        mask = 24
    }

    // find the most significant byte post-decode, if any
    for msb := zcount; msb < len(binu); msb++ {
        if binu[msb] > 0 {
            return binu[msb-zcount : outLen], nil
        }
    }

    return binu[:outLen], nil
}
