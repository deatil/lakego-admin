package baseenc

import (
    "fmt"
    "strings"
    "math/big"
)

var zero = big.NewInt(0)

/*
 * Encodings
 */

// An Encoding is a base radix encoding/decoding scheme defined by a radix-character alphabet.
type Encoding struct {
    name      string
    radix     int64
    encode    string
    decodeMap [256]byte
}

// NewEncoding returns a new Encoding defined by the given alphabet, which must
// be a radix-byte string that does not contain CR or LF ('\r', '\n').
func NewEncoding(name string, radix int64, encoder string) *Encoding {
    if int64(len(encoder)) != radix {
        panic(fmt.Sprintf("go-encoding/%s: encoding alphabet is not %d bytes long", name, radix))
    }

    for i := 0; i < len(encoder); i++ {
        if encoder[i] == '\n' || encoder[i] == '\r' {
            panic(fmt.Sprintf("go-encoding/%s: encoding alphabet contains newline character", name))
        }
    }

    enc := &Encoding{
        name:      name,
        radix:     radix,
        encode:    encoder,
        decodeMap: [256]byte{},
    }

    for i := 0; i < len(enc.decodeMap); i++ {
        enc.decodeMap[i] = 0xFF
    }

    for i := 0; i < len(encoder); i++ {
        enc.decodeMap[encoder[i]] = byte(i)
    }

    return enc
}

/*
 * Encoder
 */

// Encode encodes binary bytes into Base bytes.
func (enc *Encoding) Encode(input []byte) []byte {
    return []byte(enc.EncodeToString(input))
}

// EncodeToString encodes binary bytes into Base bytes.
func (enc *Encoding) EncodeToString(input []byte) (output string) {
    alphabet := strings.Split(enc.encode, "")

    num := new(big.Int).SetBytes(input)
    for num.Cmp(zero) > 0 {
        mod := new(big.Int)
        num.DivMod(num, big.NewInt(enc.radix), mod)
        output = alphabet[mod.Int64()] + output
    }

    for _, i := range input {
        if i != 0 {
            break
        }

        output = alphabet[0] + output
    }

    return
}

/*
 * Decoder
 */

// Decode decodes src using the encoding enc.
func (enc *Encoding) Decode(src []byte) ([]byte, error) {
    return enc.DecodeString(string(src))
}

// DecodeString decodes src using the encoding enc.
func (enc *Encoding) DecodeString(input string) (output []byte, err error) {
    result := big.NewInt(0)
    multi := big.NewInt(1)

    currBig := new(big.Int)
    for i := len(input) - 1; i >= 0; i-- {
        curr := enc.decodeMap[input[i]]
        if curr == 0xff {
            err = fmt.Errorf("go-encoding/%s: Invalid input string at character \"%s\", position %d", enc.name, string(input[i]), i)
            return
        }

        currBig.SetInt64(int64(curr))
        currBig.Mul(multi, currBig)
        result.Add(result, currBig)
        multi.Mul(multi, big.NewInt(enc.radix))
    }

    resultBytes := result.Bytes()
    var numZeros int
    for numZeros = 0; numZeros < len(input); numZeros++ {
        if(input[numZeros] != enc.encode[0]) {
            break
        }
    }

    length := numZeros + len(resultBytes)
    output = make([]byte, length)
    copy(output[numZeros:], resultBytes)

    return
}
