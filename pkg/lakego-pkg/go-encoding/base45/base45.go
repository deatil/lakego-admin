package base45

import (
    "fmt"
    "unsafe"
    "reflect"
    "strings"
    "encoding/binary"
)

const (
    base       = 45
    baseSquare = 45 * 45
    maxUint16  = 0xFFFF
)

type InvalidLengthError struct {
    length int
    mod    int
}

func (e InvalidLengthError) Error() string {
    return fmt.Sprintf("go-encoding/base45: invalid length n=%d. It should be n mod 3 = [0, 2] NOT n mod 3 = %d", e.length, e.mod)
}

type InvalidCharacterError struct {
    char     rune
    position int
}

func (e InvalidCharacterError) Error() string {
    return fmt.Sprintf("go-encoding/base45: invalid character %s at position: %d\n", string(e.char), e.position)
}

type IllegalBase45ByteError struct {
    position int
}

func (e IllegalBase45ByteError) Error() string {
    return fmt.Sprintf("go-encoding/base45: illegal base45 data at byte position %d\n", e.position)
}

// encodingMap
//   4.2.  The alphabet used in Base45
//
//   The Alphanumeric mode is defined to use 45 characters as specified in
//   this alphabet.
//
//                  Table 1: The Base45 Alphabet
//
//   Value Encoding  Value Encoding  Value Encoding  Value Encoding
//      00 0            12 C            24 O            36 Space
//      01 1            13 D            25 P            37 $
//      02 2            14 E            26 Q            38 %
//      03 3            15 F            27 R            39 *
//      04 4            16 G            28 S            40 +
//      05 5            17 H            29 T            41 -
//      06 6            18 I            30 U            42 .
//      07 7            19 J            31 V            43 /
//      08 8            20 K            32 W            44 :
//      09 9            21 L            33 X
//      10 A            22 M            34 Y
//      11 B            23 N            35 Z
const encodeStd = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// StdEncoding is the standard base62 encoding.
var StdEncoding = NewEncoding(encodeStd)

/*
 * Encodings
 */

// An Encoding is a radix 45 encoding/decoding scheme, defined by a 45-character alphabet.
type Encoding struct {
    encode    [45]byte
    decodeMap [256]byte
}

// NewEncoding returns a new padded Encoding defined by the given alphabet,
// which must be a 45-byte string that does not contain the padding character
// or CR / LF ('\r', '\n').
func NewEncoding(encoder string) *Encoding {
    if len(encoder) != 45 {
        panic("go-encoding/base45: encoding alphabet is not 45-bytes long")
    }

    for i := 0; i < len(encoder); i++ {
        if encoder[i] == '\n' || encoder[i] == '\r' {
            panic("go-encoding/base45: encoding alphabet contains newline character")
        }
    }

    e := new(Encoding)
    copy(e.encode[:], encoder)

    for i := 0; i < len(e.decodeMap); i++ {
        e.decodeMap[i] = 0xFF
    }

    for i := 0; i < len(encoder); i++ {
        e.decodeMap[encoder[i]] = byte(i)
    }

    return e
}

/*
 * Encoder
 */

// Encode
//   4.  The Base45 Encoding
//   A 45-character subset of US-ASCII is used; the 45 characters usable
//   in a QR code in Alphanumeric mode.  Base45 encodes 2 bytes in 3
//   characters, compared to Base64, which encodes 3 bytes in 4
//   characters.
//
//   For encoding two bytes [a, b] MUST be interpreted as a number n in
//   base 256, i.e. as an unsigned integer over 16 bits so that the number
//   n = (a*256) + b.
//
//   This number n is converted to base 45 [c, d, e] so that n = c +
//   (d*45) + (e*45*45).  Note the order of c, d and e which are chosen so
//   that the left-most [c] is the least significant.
//
//   The values c, d and e are then looked up in Table 1 to produce a
//   three character string.  The process is reversed when decoding.
//
//   For encoding a single byte [a], it MUST be interpreted as a base 256
//   number, i.e. as an unsigned integer over 8 bits.  That integer MUST
//   be converted to base 45 [c d] so that a = c + (45*d).  The values c
//   and d are then looked up in Table 1 to produce a two character
//   string.
//
//   A byte string [a b c d ... x y z] with arbitrary content and
//   arbitrary length MUST be encoded as follows: From left to right pairs
//   of bytes are encoded as described above.  If the number of bytes is
//   even, then the encoded form is a string with a length which is evenly
//   divisible by 3.  If the number of bytes is odd, then the last
//   (rightmost) byte is encoded on two characters as described above.
//
//   For decoding a Base45 encoded string the inverse operations are
//   performed.
func (enc *Encoding) Encode(bytes []byte) []byte {
    pairs := encodePairs(bytes)

    var builder strings.Builder
    for i, pair := range pairs {
        res := encodeBase45(pair)
        if i + 1 == len(pairs) && res[2] == 0 {
            for _, b := range res[:2] {
                if len(enc.encode) > int(b) {
                    builder.WriteByte(enc.encode[b])
                }
            }
        } else {
            for _, b := range res {
                if len(enc.encode) > int(b) {
                    builder.WriteByte(enc.encode[b])
                }
            }
        }
    }

    return []byte(builder.String())
}

// EncodeToString returns the base62 encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
    buf := enc.Encode(src)
    return string(buf)
}

/*
 * Decoder
 */

// Decode
//   Decoding example 1: The string "QED8WEX0" represents, when looked up
//   in Table 1, the values [26 14 13 8 32 14 33 0].  We arrange the
//   numbers in chunks of three, except for the last one which can be two,
//   and get [[26 14 13] [8 32 14] [33 0]].  In base 45 we get [26981
//   29798 33] where the bytes are [[105 101] [116 102] [33]].  If we look
//   at the ASCII values we get the string "ietf!".
func (enc *Encoding) Decode(in []byte) ([]byte, error) {
    size := len(in)

    mod := size % 3
    if mod != 0 && mod != 2 {
        return nil, InvalidLengthError{
            length: size,
            mod:    mod,
        }
    }

    bytes := make([]byte, 0, size)
    for pos, char := range in {
        if len(enc.decodeMap) > int(char) {
            v := enc.decodeMap[char]

            if int(v) == 255 {
                return nil, InvalidCharacterError{
                    char:     rune(char),
                    position: pos,
                }
            }

            bytes = append(bytes, v)
        }
    }

    chunks := decodeChunks(bytes)
    triplets, err := decodeTriplets(chunks)
    if err != nil {
        return nil, err
    }

    tripletsLength := len(triplets)
    decoded := make([]byte, 0, tripletsLength * 2)

    for i := 0; i < tripletsLength - 1; i++ {
        bytes := uint16ToBytes(triplets[i])
        decoded = append(decoded, bytes[0])
        decoded = append(decoded, bytes[1])
    }

    if mod == 2 {
        bytes := uint16ToBytes(triplets[tripletsLength - 1])
        decoded = append(decoded, bytes[1])
    } else {
        bytes := uint16ToBytes(triplets[tripletsLength - 1])
        decoded = append(decoded, bytes[0])
        decoded = append(decoded, bytes[1])
    }

    return decoded, nil
}

// DecodeString returns the bytes represented by the base62 string s.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return enc.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}

func uint16ToBytes(in uint16) []byte {
    bytes := make([]byte, 2)
    binary.BigEndian.PutUint16(bytes, in)
    return bytes
}

func decodeChunks(in []byte) [][]byte {
    size := len(in)
    ret := make([][]byte, 0, size / 2)
    for i := 0; i < size; i+=3 {
        var f, s, l byte
        if i + 2 < size {
            f = in[i]
            s = in[i+1]
            l = in[i+2]
            ret = append(ret, []byte{f, s, l})
        } else {
            f = in[i]
            s = in[i+1]
            ret = append(ret, []byte{f, s})
        }
    }
    return ret
}

func encodePairs(in []byte) [][]byte {
    size := len(in)
    ret := make([][]byte, 0, size / 2)
    for i := 0; i < size; i+=2 {
        var high, low byte
        if i + 1 < size {
            high = in[i]
            low = in[i+1]
        } else {
            low = in[i]
        }

        ret = append(ret, []byte{high, low})
    }

    return ret
}

func encodeBase45(in []byte) []byte {
    n := binary.BigEndian.Uint16(in)
    c := n % base
    e := (n - c) / (baseSquare)
    d := (n - (c + (e * baseSquare))) / base
    return []byte{byte(c), byte(d), byte(e)}
}

func decodeTriplets(in [][]byte) ([]uint16, error) {
    size := len(in)
    ret := make([]uint16, 0, size)

    for pos, chunk := range in {
        if len(chunk) == 3 {
            // n = c + (d*45) + (e*45*45)
            c := int(chunk[0])
            d := int(chunk[1])
            e := int(chunk[2])
            n := c + (d * base) + (e * baseSquare)

            if n > maxUint16 {
                return nil, IllegalBase45ByteError{position: pos}
            }

            ret = append(ret, uint16(n))
        }

        if len(chunk) == 2 {
            // n = c + (d*45)
            c := uint16(chunk[0])
            d := uint16(chunk[1])
            n := c + (d * base)
            ret = append(ret, n)
        }
    }

    return ret, nil
}
