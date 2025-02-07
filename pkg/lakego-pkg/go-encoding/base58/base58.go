package base58

import (
    "unsafe"
    "reflect"
    "strconv"
    "math/big"
)

var bigRadix = [...]*big.Int{
    big.NewInt(0),
    big.NewInt(58),
    big.NewInt(58 * 58),
    big.NewInt(58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
    big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58),
    bigRadix10,
}

var bigRadix10 = big.NewInt(58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58 * 58) // 58^10

const (
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    alphabetIdx0 = '1'
)

type CorruptInputError int64

func (e CorruptInputError) Error() string {
    return "go-encoding/base58: illegal base58 data at input byte " + strconv.FormatInt(int64(e), 10)
}

var StdEncoding = NewEncoding(alphabet)

/*
 * Encodings
 */

// An Encoding is a base 58 encoding/decoding scheme defined by a 58-character alphabet.
type Encoding struct {
    encode    [58]byte
    decodeMap [256]byte
}

// NewEncoding returns a new Encoding defined by the given alphabet, which must
// be a 58-byte string that does not contain CR or LF ('\r', '\n').
func NewEncoding(encoder string) *Encoding {
    if len(encoder) != 58 {
        panic("go-encoding/base58: encoding alphabet is not 58 bytes long")
    }

    for i := 0; i < len(encoder); i++ {
        if encoder[i] == '\n' || encoder[i] == '\r' {
            panic("go-encoding/base58: encoding alphabet contains newline character")
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

// Encode encodes src using the encoding enc.
func (enc *Encoding) Encode(b []byte) []byte {
    x := new(big.Int)
    x.SetBytes(b)

    maxlen := int(float64(len(b))*1.365658237309761) + 1
    answer := make([]byte, 0, maxlen)
    mod := new(big.Int)

    for x.Sign() > 0 {
        x.DivMod(x, bigRadix10, mod)
        if x.Sign() == 0 {
            m := mod.Int64()
            for m > 0 {
                answer = append(answer, enc.encode[m%58])
                m /= 58
            }
        } else {
            m := mod.Int64()
            for i := 0; i < 10; i++ {
                answer = append(answer, enc.encode[m%58])
                m /= 58
            }
        }
    }

    for _, i := range b {
        if i != 0 {
            break
        }

        answer = append(answer, alphabetIdx0)
    }

    alen := len(answer)
    for i := 0; i < alen/2; i++ {
        answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
    }

    return answer
}

// EncodeToString returns the base58 encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
    answer := enc.Encode(src)

    return string(answer)
}

/*
 * Decoder
 */

// Decode decodes src using the encoding enc. It writes at most DecodedLen(len(src))
// bytes to dst and returns the number of bytes written. If src contains invalid base58
// data, it will return the number of bytes successfully written and CorruptInputError.
func (enc *Encoding) Decode(src []byte) ([]byte, error) {
    answer := big.NewInt(0)
    scratch := new(big.Int)

    b := string(src)

    for t := b; len(t) > 0; {
        n := len(t)
        if n > 10 {
            n = 10
        }

        total := uint64(0)
        for _, v := range t[:n] {
            if v > 255 {
                return []byte(""), CorruptInputError(v)
            }

            tmp := enc.decodeMap[v]
            if tmp == 255 {
                return []byte(""), CorruptInputError(v)
            }

            total = total*58 + uint64(tmp)
        }

        answer.Mul(answer, bigRadix[n])
        scratch.SetUint64(total)
        answer.Add(answer, scratch)

        t = t[n:]
    }

    tmpval := answer.Bytes()

    var numZeros int
    for numZeros = 0; numZeros < len(b); numZeros++ {
        if b[numZeros] != alphabetIdx0 {
            break
        }
    }

    flen := numZeros + len(tmpval)
    val := make([]byte, flen)
    copy(val[numZeros:], tmpval)

    return val, nil
}

// DecodeString returns the bytes represented by the base58 string s.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return enc.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}

