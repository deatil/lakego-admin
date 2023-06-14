package ber

import "reflect"

func encodeInt(value reflect.Value) ([]byte, error) {
    switch value.Kind() {
        case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
        default:
            return nil, invalidTypeError("integer", value)
    }

    n := value.Int()
    length := intLength(n)

    buf := make([]byte, length)
    for i := 0; i < length; i++ {
        shift := uint((length - 1 - i) * 8)
        buf[i] = byte(n >> shift)
    }

    return buf, nil
}

func intLength(i int64) (length int) {
    length = 1

    for i > 127 {
        length++
        i >>= 8
    }

    for i < -128 {
        length++
        i >>= 8
    }

    return
}
