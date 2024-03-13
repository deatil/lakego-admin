package quotedprintable

import (
    "io"
    "fmt"
    "bytes"
    "unsafe"
    "reflect"
)

const (
    stdEncoder  = "0123456789ABCDEF"
    encoderSize = len(stdEncoder)
)

var invalidEncoderSize = fmt.Errorf("quotedprintable: reflect str lenght must be %d.", encoderSize)

var StdEncoding, _ = NewEncoding(stdEncoder)

type Encoding struct {
    encoder string
}

func NewEncoding(encoder string) (*Encoding, error) {
    if len(encoder) != encoderSize {
        return nil, invalidEncoderSize
    }

    return &Encoding{encoder: encoder}, nil
}

func (e *Encoding) EncodedLen(n int) int {
    return 3 * n
}

func (e *Encoding) Encode(src []byte) ([]byte, error) {
    dst := make([]byte, e.EncodedLen(len(src)))

    n := 0
    for i, c := range src {
        switch {
            case c != '=' && (c >= '!' && c <= '~' || c == '\n' || c == '\r'):
                dst[n] = c
                n++
            case c == ' ' || c == '\t':
                if isLastChar(i, src) {
                    e.encodeByte(dst[n:], c)
                    n += 3
                } else {
                    dst[n] = c
                    n++
                }
            default:
                e.encodeByte(dst[n:], c)
                n += 3
        }
    }

    return dst[:n], nil
}

// EncodeToString returns the PunyEncoding encoding of src.
func (e *Encoding) EncodeToString(src []byte) (string, error) {
    buf, err := e.Encode(src)
    return string(buf), err
}

func (e *Encoding) DecodedLen(n int) int {
    return n
}

func (e *Encoding) Decode(src []byte) ([]byte, error) {
    dst := make([]byte, e.DecodedLen(len(src)))

    var eol, trimLen, eolLen, n int
    var err error

    for i := 0; i < len(src); i++ {
        if i == eol {
            eol = bytes.IndexByte(src[i:], '\n') + i + 1
            if eol == i {
                eol = len(src)
                eolLen = 0
            } else if eol-2 >= i && src[eol-2] == '\r' {
                eolLen = 2
            } else {
                eolLen = 1
            }

            // Count the number of bytes to trim
            trimLen = 0
            for {
                if trimLen == eol-eolLen-i {
                    break
                }

                switch src[eol-eolLen-trimLen-1] {
                    case '\n', '\r', ' ', '\t':
                        trimLen++
                        continue
                    case '=':
                        if trimLen > 0 {
                            trimLen += eolLen + 1
                            eolLen = 0
                            err = fmt.Errorf("quotedprintable: invalid bytes after =: %q", src[eol-trimLen+1:eol])
                        } else {
                            trimLen = eolLen + 1
                            eolLen = 0
                        }
                }

                break
            }
        }

        // Skip trimmable bytes
        if trimLen > 0 && i == eol-trimLen-eolLen {
            if err != nil {
                return nil, err
            }

            i += trimLen - 1
            continue
        }

        switch c := src[i]; {
            case c == '=':
                if i+2 >= len(src) {
                    return nil, io.ErrUnexpectedEOF
                }
                b, convErr := readHexByte(src[i+1:])
                if convErr != nil {
                    return nil, convErr
                }
                dst[n] = b
                n++
                i += 2
            case (c >= ' ' && c <= '~') || c == '\n' || c == '\r' || c == '\t':
                dst[n] = c
                n++
            default:
                return nil, fmt.Errorf("quotedprintable: invalid unescaped byte 0x%02x in quoted-printable body", c)
        }
    }

    return dst[:n], nil
}

// DecodeString returns the bytes represented by the PunyEncoding string s.
func (e *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return e.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}

func (e *Encoding) encodeByte(dst []byte, b byte) {
    dst[0] = '='
    dst[1] = e.encoder[b>>4]
    dst[2] = e.encoder[b&0x0f]
}
