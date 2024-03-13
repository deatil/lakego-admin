package puny

import (
    "fmt"
    "bytes"
    "errors"
    "unsafe"
    "reflect"
)

const (
    // Bootstring parameters specified in RFC 3492
    baseC            = 36
    tMin             = 1
    tMax             = 26
    skew             = 38
    damp             = 700
    initialBias      = 72
    initialN         = 128  // 0x80
    delimiter   byte = 0x2D // hyphen
    maxRune          = '\U0010FFFF'
)

var (
    invalidCharaterErr = errors.New("Non-ASCCI codepoint found in src")
    overFlowErr        = errors.New("Overflow")
    inputError         = errors.New("Bad Input")
    digit2codepointErr = errors.New("digit2codepoint")
)

// std Encoding
var StdEncoding = NewPunyEncoding()

type Encoding struct{}

func NewPunyEncoding() *Encoding {
    return &Encoding{}
}

func (p *Encoding) EncodedLen(n int) int {
    return n
}

func (p *Encoding) Encode(src []byte) ([]byte, error) {
    n := initialN
    delta := 0
    bias := initialBias
    runes := bytes.Runes(src)

    var result bytes.Buffer
    var err error

    basicRunes := 0
    for i := 0; i < len(runes); i++ {
        // Write all basic codepoints to result
        if runes[i] < 0x80 {
            result.WriteRune(runes[i])

            basicRunes++
        }
    }

    // Append delimiter
    if basicRunes > 0 {
        err = result.WriteByte(delimiter)
        if err != nil {
            return nil, err
        }
    }

    for h := basicRunes; h < len(runes); {
        minRune := maxRune

        // Find the minimum rune >= n in the input
        for i := 0; i < len(runes); i++ {
            if int(runes[i]) >= n && runes[i] < minRune {
                minRune = runes[i]
            }
        }

        delta = delta + (int(minRune)-n)*(h+1) // ??
        n = int(minRune)

        for i := 0; i < len(runes); i++ {
            if int(runes[i]) < n {
                delta++
            }
            if int(runes[i]) == n {
                q := delta
                for k := baseC; true; k += baseC {
                    var t int

                    switch {
                        case k <= bias:
                            t = tMin
                            break
                        case k >= (bias + tMax):
                            t = tMax
                            break
                        default:
                            t = k - bias
                    }

                    if q < t {
                        break
                    }

                    result, err = writeBytesDigitToCodepoint(result, t+(q-t)%(baseC-t))
                    if err != nil {
                        return nil, err
                    }
                    q = (q - t) / (baseC - t)
                }
                result, err = writeBytesDigitToCodepoint(result, q)
                if err != nil {
                    return nil, err
                }

                bias = adapt(delta, h == basicRunes, h+1)
                delta = 0
                h++
            }
        }
        delta++
        n++
    }

    return result.Bytes(), nil
}

// EncodeToString returns the puny encoding of src.
func (p *Encoding) EncodeToString(src []byte) (string, error) {
    buf, err := p.Encode(src)
    return string(buf), err
}

func (p *Encoding) DecodedLen(n int) int {
    return n
}

func (p *Encoding) Decode(src []byte) ([]byte, error) {
    // Decoding procedure explained in detail in RFC 3492.
    n := initialN
    i := 0
    bias := initialBias

    pos := 0
    delimIndex := -1

    result := make([]rune, 0, len(src))

    // Only ASCII allowed in decoding procedure
    for j := 0; j < len(src); j++ {
        if src[j] >= 0x80 {
            return nil, invalidCharaterErr

        }
    }

    // Consume all codepoints before the last delimiter
    delimIndex = bytes.LastIndex(src, []byte{delimiter})
    for pos = 0; pos < delimIndex; pos++ {
        result = append(result, rune(src[pos]))
    }

    // Consume delimiter
    pos = delimIndex + 1

    for pos < len(src) {
        oldi := i
        w := 1
        for k := baseC; true; k += baseC {
            var t int

            if pos == len(src) {
                return nil, inputError
            }

            // consume a code point, or fail if there was none to consume
            cp := rune(src[pos])
            pos++

            digit := codepoint2digit(cp)

            if digit > ((maxRune - i) / w) {
                return nil, inputError
            }

            i = i + digit*w

            switch {
                case k <= bias:
                    t = tMin
                    break
                case k >= bias+tMax:
                    t = tMax
                    break
                default:
                    t = k - bias
            }

            if digit < t {
                break
            }
            w = w * (baseC - t)
        }
        bias = adapt(i-oldi, oldi == 0, len(result)+1)

        if i/(len(result)+1) > (maxRune - n) {
            return nil, overFlowErr
        }

        n = n + i/(len(result)+1)
        i = i % (len(result) + 1)

        if n < 0x80 {
            return nil, fmt.Errorf("%v is a basic code point.", n)
        }

        result = insert(result, i, rune(n))
        i++
    }

    return writeRune(result), nil
}

// DecodeString returns the bytes represented by the puny string s.
func (p *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return p.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}
