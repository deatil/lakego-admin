package ber

import (
    "bytes"
    "reflect"
)

func encodeStruct(value reflect.Value) ([]byte, error) {
    if value.Kind() != reflect.Struct {
        return nil, invalidTypeError("struct", value)
    }

    buf := new(bytes.Buffer)
    for i := 0; i < value.NumField(); i++ {
        fieldVal := value.Field(i)
        fieldStruct := value.Type().Field(i)

        if fieldVal.CanInterface() {
            tag := fieldStruct.Tag.Get(tagKey)
            b, err := MarshalWithOptions(fieldVal.Interface(), tag)
            if err != nil {
                return nil, err
            }

            buf.Write(b)
        }
    }

    return buf.Bytes(), nil
}
