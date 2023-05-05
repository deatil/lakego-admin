package encode

import "reflect"

func encodeOctetString(value reflect.Value) ([]byte, error) {
    kind := value.Kind()

    if !(kind == reflect.Array || kind == reflect.Slice) || value.Type().Elem().Kind() != reflect.Uint8 {
        return nil, invalidTypeError("byte array/slice", value)
    }

    if kind == reflect.Slice {
        return value.Interface().([]byte), nil
    }

    data := make([]byte, value.Len())
    for i := 0; i < value.Len(); i++ {
        data[i] = byte(value.Index(i).Interface().(byte))
    }

    return data, nil
}
