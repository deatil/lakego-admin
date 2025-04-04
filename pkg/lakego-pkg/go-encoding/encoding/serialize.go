package encoding

import (
    "bytes"
    "reflect"
    "strconv"
    "encoding/gob"
)

// Serialize Encode
func (this Encoding) SerializeEncode(data any) Encoding {
    this.data, this.Error = serialize(data)

    return this
}

// Serialize Decode
func (this Encoding) SerializeDecode(val any) Encoding {
    this.Error = unserialize(this.data, val)

    return this
}

// serialize
func serialize(value any) ([]byte, error) {
    if bytes, ok := value.([]byte); ok {
        return bytes, nil
    }

    switch v := reflect.ValueOf(value); v.Kind() {
        case reflect.Int,
            reflect.Int8,
            reflect.Int16,
            reflect.Int32,
            reflect.Int64:
            return []byte(strconv.FormatInt(v.Int(), 10)), nil
        case reflect.Uint,
            reflect.Uint8,
            reflect.Uint16,
            reflect.Uint32,
            reflect.Uint64:
            return []byte(strconv.FormatUint(v.Uint(), 10)), nil
    }

    var b bytes.Buffer
    encoder := gob.NewEncoder(&b)

    if err := encoder.Encode(value); err != nil {
        return nil, err
    }

    return b.Bytes(), nil
}

// unserialize
func unserialize(data []byte, ptr any) (err error) {
    if bytes, ok := ptr.(*[]byte); ok {
        *bytes = data
        return nil
    }

    if v := reflect.ValueOf(ptr); v.Kind() == reflect.Ptr {
        switch p := v.Elem(); p.Kind() {
            case reflect.Int,
                reflect.Int8,
                reflect.Int16,
                reflect.Int32,
                reflect.Int64:
                var i int64
                i, err = strconv.ParseInt(string(data), 10, 64)
                if err != nil {
                    return err
                }

                p.SetInt(i)
                return nil

            case reflect.Uint,
                reflect.Uint8,
                reflect.Uint16,
                reflect.Uint32,
                reflect.Uint64:
                var i uint64
                i, err = strconv.ParseUint(string(data), 10, 64)
                if err != nil {
                    return err
                }

                p.SetUint(i)
                return nil
        }
    }

    b := bytes.NewBuffer(data)
    decoder := gob.NewDecoder(b)

    if err = decoder.Decode(ptr); err != nil {
        return err
    }

    return nil
}
