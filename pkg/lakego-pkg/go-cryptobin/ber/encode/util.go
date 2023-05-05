package encode

import (
    "bytes"
    "reflect"
    "strings"
)

func cut(s, sep string) (before, after string, found bool) {
    if i := strings.Index(s, sep); i >= 0 {
        return s[:i], s[i+len(sep):], true
    }
    return s, "", false
}

func reverseBytes(b []byte) []byte {
    for i, j := 0, len(b)-1; i < len(b)/2; i++ {
        b[i], b[j-i] = b[j-i], b[i]
    }
    return b
}

func encodeUint(n uint64) []byte {
    length := uintLength(n)
    buf := make([]byte, length)
    for i := 0; i < length; i++ {
        shift := uint((length - 1 - i) * 8)
        buf[i] = byte(n >> int(shift))
    }
    return buf
}

func uintLength(i uint64) (length int) {
    length = 1
    for i > 255 {
        length++
        i >>= 8
    }
    return
}

// https://en.wikipedia.org/wiki/Variable-length_quantity
func encodeBase128(num uint64) []byte {
    buf := new(bytes.Buffer)

    for num != 0 {
        i := num & 0x7f
        num >>= 7

        if len(buf.Bytes()) != 0 {
            i |= 0x80
        }
        buf.WriteByte(byte(i))
    }

    return reverseBytes(buf.Bytes())
}

func empty(value reflect.Value) bool {
    defaultValue := reflect.Zero(value.Type())
    return reflect.DeepEqual(value.Interface(), defaultValue.Interface())
}
