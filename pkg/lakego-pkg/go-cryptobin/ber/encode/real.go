package encode

import (
    "bytes"
    "math"
    "reflect"
    "strconv"
)

func encodeReal(value reflect.Value) ([]byte, error) {
    // ECMA-63
    // https://www.ecma-international.org/wp-content/uploads/ECMA-63_1st_edition_september_1980.pdf

    switch value.Kind() {
    case reflect.Float32, reflect.Float64:
    default:
        return nil, invalidTypeError("float", value)
    }

    n := value.Float()

    switch {
    case math.IsInf(n, 1):
        return []byte{0x40}, nil
    case math.IsInf(n, -1):
        return []byte{0x41}, nil
    case math.IsNaN(n):
        return []byte{0x42}, nil
    case n == 0.0:
        if math.Signbit(n) {
            return []byte{0x43}, nil
        }
    default:
        nStr := []byte(strconv.FormatFloat(n, 'G', -1, 64))
        var buf []byte
        if bytes.Contains(nStr, []byte{'E'}) {
            buf = []byte{0x03}
        } else {
            buf = []byte{0x02}
        }
        buf = append(buf, nStr...)
        return buf, nil
    }
    return nil, nil
}
