package encode

import (
    "bytes"
    "fmt"
    "io"
    "reflect"
)

const (
    tagKey = "asn1"
)

func Marshal(v any) ([]byte, error) {
    return MarshalWithOptions(v, "")
}

func MarshalWithOptions(v any, opts string) ([]byte, error) {
    buf := new(bytes.Buffer)
    err := NewEncoder(buf).Encode(v, opts)
    if err != nil {
        return nil, err
    }
    return buf.Bytes(), nil
}

type Encoder struct {
    w            io.Writer
    buf          *bytes.Buffer
    bodyBuf      *bytes.Buffer
    encodingFunc func(reflect.Value) ([]byte, error)
    options      *options
}

func NewEncoder(w io.Writer) *Encoder {
    buf := new(bytes.Buffer)
    bodyBuf := new(bytes.Buffer)
    return &Encoder{
        w:       w,
        buf:     buf,
        bodyBuf: bodyBuf,
    }
}

func (e *Encoder) Encode(v any, opts string) error {
    return e.encode(reflect.ValueOf(v), opts)
}

func (e *Encoder) parseType(v reflect.Value) (tag Tag, isConstructed bool, err error) {
    switch v.Type() {
        case oidType:
            e.encodingFunc = encodeObjectIdentifier
            tag = TagObjectIdentifier
        case timeType:
            tag = e.options.timeType
            switch e.options.timeType {
            case TagUTCTime:
                e.encodingFunc = encodeUTCTime
            default:
                e.encodingFunc = encodeGeneralizedTime
            }
    }

    if e.encodingFunc == nil {
        switch v.Kind() {
        case reflect.Bool:
            e.encodingFunc = encodeBool
            tag = TagBoolean
        case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
            e.encodingFunc = encodeInt
            tag = TagInteger
        case reflect.Float32, reflect.Float64:
            e.encodingFunc = encodeReal
            tag = TagReal
        case reflect.String:
            tag = e.options.stringType
            e.encodingFunc = encodeString
            switch e.options.stringType {
            case TagPrintableString:
                if !isValidPrintableString(v.String()) {
                    return tag, isConstructed, fmt.Errorf("string not valid printablestring")
                }
            case TagIA5String:
                if !isValidIA5String(v.String()) {
                    return tag, isConstructed, fmt.Errorf("string not valid ia5string")
                }
            case TagNumericString:
                if !isValidNumericString(v.String()) {
                    return tag, isConstructed, fmt.Errorf("string not valid numeric string")
                }
            case TagBitString:
                e.encodingFunc = EncodeBitString
            }
        case reflect.Struct:
            e.encodingFunc = encodeStruct
            isConstructed = true
            tag = TagSet
        case reflect.Array, reflect.Slice:
            if v.Type().Elem().Kind() == reflect.Uint8 {
                e.encodingFunc = encodeOctetString
                tag = TagOctetString
            } else {
                e.encodingFunc = encodeSequence
                tag = TagSequence
                isConstructed = true
            }
        default:
            return tag, isConstructed, fmt.Errorf("unsupported go type '%s'", v.Type())
        }
    }
    return tag, isConstructed, nil
}

func (e *Encoder) encode(v reflect.Value, opts string) error {

    options, err := parseOptions(opts)
    if err != nil {
        return err
    }
    e.options = options

    tag, isConstructed, err := e.parseType(v)
    if err != nil {
        return err
    }

    if options.explicit {
        if options.tag == nil {
            return fmt.Errorf("flag 'explicit' requires flag 'tag' to be set")
        }
        body, err := e.encodingFunc(v)
        if err != nil {
            return err
        }
        e.bodyBuf.Write(body)

        e.encodeHeader(TagClassUniversal, tag, true)
        e.buf.Write(e.bodyBuf.Bytes())

        e.bodyBuf.Reset()
        e.bodyBuf.Write(e.buf.Bytes())
        e.buf.Reset()

        isConstructed = true
    }

    emptyValue := empty(v)
    if !emptyValue && !options.optional && e.bodyBuf.Len() == 0 {
        body, err := e.encodingFunc(v)
        if err != nil {
            return err
        }
        e.bodyBuf.Write(body)
    }

    class := TagClassUniversal
    if options.tag != nil {
        if options.application {
            class = TagClassApplication
        } else if options.private {
            class = TagClassPrivate
        } else {
            class = TagClassContextSpecific
        }
        tag = Tag(*options.tag)
    }

    if options.private {
        class = TagClassPrivate
    }

    e.encodeHeader(class, tag, isConstructed)
    e.buf.Write(e.bodyBuf.Bytes())

    _, err = e.w.Write(e.buf.Bytes())
    if err != nil {
        return err
    }

    return nil

}

func (e *Encoder) encodeHeader(class TagClass, tag Tag, isConstructed bool) {
    e.encodeIdentifier(class, tag, isConstructed)
    e.encodeLength()
}

func (e *Encoder) encodeIdentifier(class TagClass, tag Tag, isConstructed bool) {
    b := []byte{0x00}

    b[0] |= byte(class << 6)

    if isConstructed {
        b[0] |= byte(1 << 5)
    } else {
        b[0] |= byte(0 << 5)
    }

    // universal tags 0-30
    if tag <= 30 {
        b[0] |= byte(tag)
    } else {
        b[0] |= byte(0x1f)
        b = append(b, encodeBase128(uint64(tag))...)
    }

    e.buf.Write(b)
}

func (e *Encoder) encodeLength() {
    // only definite form supported
    // length encoded as unsigned binary integers

    length := e.bodyBuf.Len()
    b := new(bytes.Buffer)

    lengthBytes := encodeUint(uint64(length))

    // short form
    if length <= 0x7f {
        e.buf.Write(lengthBytes)
        return
    }

    // long form
    header := len(lengthBytes) | 0x80

    b.Write(encodeUint(uint64(header)))
    b.Write(lengthBytes)
    e.buf.Write(b.Bytes())
}

func encodeSequence(v reflect.Value) ([]byte, error) {
    switch v.Kind() {
    case reflect.Array, reflect.Slice:
    default:
        return nil, invalidTypeError("array/slice", v)
    }

    buf := new(bytes.Buffer)
    for i := 0; i < v.Len(); i++ {
        b, err := Marshal(v.Index(i).Interface())
        if err != nil {
            return nil, err
        }
        buf.Write(b)
    }
    return buf.Bytes(), nil
}

func invalidTypeError(expected string, value reflect.Value) error {
    return fmt.Errorf("invalid go type '%s', expecting '%s'", value.Type(), expected)
}
