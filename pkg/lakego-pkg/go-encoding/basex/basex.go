package basex

import (
    "fmt"
    "bytes"
    "errors"
    "unsafe"
    "reflect"
    "strconv"
    "math/big"
)

const (
    encodeBase2         = "01"
    encodeBase16        = "0123456789ABCDEF"
    encodeBase16Invalid = "0123456789abcdef"
    encodeBase32        = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    encodeBase36        = "0123456789abcdefghijklmnopqrstuvwxyz"
    encodeBase58        = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encodeBase62        = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    encodeBase62Random  = "vPh7zZwA2LyU4bGq5tcVfIMxJi6XaSoK9CNp0OWljYTHQ8REnmu31BrdgeDkFs"
    encodeBase62Invalid = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
    Base2Encoding         = NewEncoding(encodeBase2)
    Base16Encoding        = NewEncoding(encodeBase16)
    Base16InvalidEncoding = NewEncoding(encodeBase16Invalid)
    Base32Encoding        = NewEncoding(encodeBase32)
    Base36Encoding        = NewEncoding(encodeBase36)
    Base58Encoding        = NewEncoding(encodeBase58)
    Base62Encoding        = NewEncoding(encodeBase62)
    Base62RandomEncoding  = NewEncoding(encodeBase62Random)
    Base62InvalidEncoding = NewEncoding(encodeBase62Invalid)
)

/*
 * Encodings
 */

// An Encoding is a base radix encoding/decoding scheme defined by a radix-character alphabet.
type Encoding struct {
    encode    []rune
    decodeMap map[rune]int
    radix     *big.Int
}

// NewEncoding returns a new Encoding defined by the given alphabet, which must
// be a radix-byte string that does not contain CR or LF ('\r', '\n').
// Example alphabets:
//   - base2: 01
//   - base16: 0123456789abcdef
//   - base32: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
//   - base58: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
//   - base62: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
func NewEncoding(encoder string) *Encoding {
    for i := 0; i < len(encoder); i++ {
        if encoder[i] == '\n' || encoder[i] == '\r' {
            panic("go-encoding/basex: encoding alphabet contains newline character")
        }
    }

    runes := []rune(encoder)
    decodeMap := make(map[rune]int)

    enc := &Encoding{}

    for i := 0; i < len(runes); i++ {
        if _, ok := decodeMap[runes[i]]; ok {
            panic("go-encoding/basex: Ambiguous alphabet.")
        }

        decodeMap[runes[i]] = i
    }

    enc.encode = runes
    enc.decodeMap = decodeMap
    enc.radix = big.NewInt(int64(len(runes)))

    return enc
}

/*
 * Encoder
 */

// Encode encodes binary bytes into bytes.
func (enc *Encoding) Encode(source []byte) []byte {
    if len(source) == 0 {
        return nil
    }

    var (
        res bytes.Buffer
        k   = 0
    )

    for ; source[k] == 0 && k < len(source)-1; k++ {
        res.WriteRune(enc.encode[0])
    }

    var (
        mod big.Int
        sourceInt = new(big.Int).SetBytes(source)
    )

    for sourceInt.Uint64() > 0 {
        sourceInt.DivMod(sourceInt, enc.radix, &mod)
        res.WriteRune(enc.encode[mod.Uint64()])
    }

    var (
        buf = res.Bytes()
        j   = len(buf) - 1
    )

    for k < j {
        buf[k], buf[j] = buf[j], buf[k]
        k++
        j--
    }

    return buf
}

// EncodeToString returns the basex encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
    buf := enc.Encode(src)
    return string(buf)
}

// Decode decodes src using the encoding enc.
func (enc *Encoding) Decode(source []byte) ([]byte, error) {
    if len(source) == 0 {
        return nil, nil
    }

    var (
        data = []rune(string(source))
        dest = big.NewInt(0)
    )

    for i := 0; i < len(data); i++ {
        value, ok := enc.decodeMap[data[i]]
        if !ok {
            return nil, errors.New("go-encoding/basex: non Base Character")
        }

        dest.Mul(dest, enc.radix)
        if value > 0 {
            dest.Add(dest, big.NewInt(int64(value)))
        }
    }

    k := 0
    for ; data[k] == enc.encode[0] && k < len(data)-1; k++ {
    }

    buf := dest.Bytes()
    res := make([]byte, k, k+len(buf))

    return append(res, buf...), nil
}

// DecodeString returns the bytes represented by the basex string s.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return enc.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}

// 补码
func (enc *Encoding) padding(s string, minlen int) string {
    if len(s) >= minlen {
        return s
    }

    format := fmt.Sprint(`%0`, strconv.Itoa(minlen), "s")
    return fmt.Sprintf(format, s)
}
