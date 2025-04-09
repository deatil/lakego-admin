package chaocipher

import (
    "unsafe"
    "reflect"
    "errors"
    "strings"
    "unicode/utf8"
)

const (
    lEncodeStd = "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
    rEncodeStd = "PTLNBQDEOYSFAVZKGJRIHWXUMC"
)

// StdEncoding is the standard chaocipher encoding.
var StdEncoding = NewEncoding(lEncodeStd, rEncodeStd)

/*
 * Encodings
 */

// An Encoding is a radix 62 encoding/decoding scheme, defined by a 62-character alphabet.
type Encoding struct {
    lAlphabet string
    rAlphabet string
}

// NewEncoding returns a new padded Encoding defined by the given alphabet,
// which must be a 62-byte string that does not contain the padding character
// or CR / LF ('\r', '\n').
func NewEncoding(lAlphabet, rAlphabet string) *Encoding {
    if len(lAlphabet) != 26 || len(rAlphabet) != 26 {
        panic("go-encoding/chaocipher: encoding alphabet is not 26-bytes long")
    }

    for i := 0; i < len(lAlphabet); i++ {
        if lAlphabet[i] == '\n' || lAlphabet[i] == '\r' {
            panic("go-encoding/chaocipher: encoding lAlphabet contains newline character")
        }
    }
    for i := 0; i < len(rAlphabet); i++ {
        if rAlphabet[i] == '\n' || rAlphabet[i] == '\r' {
            panic("go-encoding/chaocipher: encoding rAlphabet contains newline character")
        }
    }

    e := new(Encoding)
    e.lAlphabet = lAlphabet
    e.rAlphabet = rAlphabet

    return e
}

/*
 * Encoder
 */

// Encode encodes src using the encoding enc.
func (enc *Encoding) Encode(src []byte) []byte {
    if len(src) == 0 {
        return nil
    }

    dst, err := enc.chao(string(src), true)
    if err != nil {
        return nil
    }

    return []byte(dst)
}

// EncodeToString returns the chao encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
    buf := enc.Encode(src)
    return string(buf)
}

/*
 * Decoder
 */

// Decode decodes src using the encoding enc.
func (enc *Encoding) Decode(src []byte) ([]byte, error) {
    if len(src) == 0 {
        return nil, nil
    }

    dst, err := enc.chao(string(src), false)
    if err != nil {
        return nil, err
    }

    return []byte(dst), nil
}

// DecodeString returns the bytes represented by the chao string s.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return enc.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}

func (enc *Encoding) chao(text string, encrypt bool) (string, error) {
    len := len(text)
    if utf8.RuneCountInString(text) != len {
        return "", errors.New("go-cryptobin/chaocipher: Text contains non-ASCII characters")
    }

    left := enc.lAlphabet
    right := enc.rAlphabet

    eText := make([]byte, len)
    temp := make([]byte, 26)

    for i := 0; i < len; i++ {
        var index int
        if encrypt {
            index = strings.IndexByte(right, text[i])
            eText[i] = left[index]
        } else {
            index = strings.IndexByte(left, text[i])
            eText[i] = right[index]
        }

        if i == len-1 {
            break
        }

        for j := index; j < 26; j++ {
            temp[j-index] = left[j]
        }
        for j := 0; j < index; j++ {
            temp[26-index+j] = left[j]
        }

        store := temp[1]
        for j := 2; j < 14; j++ {
            temp[j-1] = temp[j]
        }

        temp[13] = store
        left = string(temp[:])

        for j := index; j < 26; j++ {
            temp[j-index] = right[j]
        }
        for j := 0; j < index; j++ {
            temp[26-index+j] = right[j]
        }

        store = temp[0]
        for j := 1; j < 26; j++ {
            temp[j-1] = temp[j]
        }

        temp[25] = store
        store = temp[2]
        for j := 3; j < 14; j++ {
            temp[j-1] = temp[j]
        }

        temp[13] = store
        right = string(temp[:])
    }

    return string(eText[:]), nil
}
