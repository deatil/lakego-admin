package ber

import "reflect"

func encodeBool(value reflect.Value) ([]byte, error) {
    switch value.Kind() {
        case reflect.Bool:
        default:
            return nil, invalidTypeError("bool", value)
    }

    if value.Bool() {
        return []byte{0xff}, nil
    }

    return []byte{0x00}, nil
}
