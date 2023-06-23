package asn1

import (
    "fmt"
    "time"
    "bytes"
    "reflect"
    "math/big"
)

const (
    tagKey = "asn1"
)

func Marshal(v any) ([]byte, error) {
    return MarshalWithOptions(v, "")
}

func MarshalWithOptions(v any, optionsString string) ([]byte, error) {
    options, err := parseOptions(optionsString)
    if err != nil {
        return nil, err
    }

    enc := NewEncoder(v, options)

    b, err := enc.encode()
    if err != nil {
        return nil, err
    }

    return b, nil
}

type encoder interface {
    length() int
    encode() ([]byte, error)
}

func NewEncoder(v any, opts *options) Encoder {
    buf := new(bytes.Buffer)

    return Encoder{buf, v, opts}
}

type Encoder struct {
    buf *bytes.Buffer

    v    any
    opts *options
}

func getChoiceIndex(val reflect.Value) (int, error) {
    kind := val.Kind()
    if kind != reflect.Struct {
        return -1, fmt.Errorf("invalid 'choice' type '%s', must be struct", kind.String())
    }

    choiceIndex := 0
    choiceFound := false

    for i := 0; i < val.NumField(); i++ {
        choice := val.Field(i).Interface()
        if !reflect.DeepEqual(choice, reflect.Zero(val.Field(i).Type()).Interface()) {
            if choiceFound {
                return -1, fmt.Errorf("choice value has multiple fields set")
            }

            choiceIndex = i
            choiceFound = true
        }
    }

    return choiceIndex, nil
}

func (b Encoder) length() int {
    return b.buf.Len()
}

func (e Encoder) encode() (encodedContents []byte, err error) {
    val := reflect.ValueOf(e.v)

    // handle interface type
    if val.Kind() == reflect.Interface {
        val = val.Elem()
    }

    if !val.IsValid() {
        return nil, fmt.Errorf("asn1: cannot marshal nil value")
    }

    var contentsEncoder encoder

    if val.Kind() == reflect.Slice && val.Len() == 0 && e.opts.omitEmpty {
        return []byte(nil), nil
    }

    id := identifier{
        isConstructed: false,
        class:         TagClassUniversal,
    }

    empty := isEmpty(val)

    if empty && e.opts.optional {
        return []byte(nil), nil
    }

    if e.opts.defaultValue != nil {
        if canHaveDefaultValue(val.Kind()) {
            defaultValue := reflect.New(val.Type()).Elem()
            defaultValue.SetInt(*e.opts.defaultValue)

            if reflect.DeepEqual(val.Interface(), defaultValue.Interface()) {
                return []byte(nil), nil
            }

        }
    }

    if e.opts.choice {
        choiceIndex, err := getChoiceIndex(val)
        if err != nil {
            return nil, err
        }

        if e.opts.tag != nil {
            tag := val.Type().Field(choiceIndex).Tag.Get(tagKey)
            tagOpts, err := parseOptions(tag)
            if err != nil {
                return nil, err
            }
            encodedContents, err = NewEncoder(val.Field(choiceIndex).Interface(), tagOpts).encode()
            if err != nil {
                return nil, err
            }
        } else {
            choiceTag := val.Type().Field(choiceIndex).Tag.Get(tagKey)
            e.opts, err = parseOptions(choiceTag)
            if err != nil {
                return nil, err
            }
            val = reflect.ValueOf(val.Field(choiceIndex).Interface())
        }

    }

    if val.Type() == rawValueType {
        rv := val.Interface().(RawValue)
        if len(rv.FullBytes) != 0 {
            return bytesEncoder(rv.FullBytes), nil
        }

        t := new(taggedEncoder)

        t.tag = bytesEncoder(appendTagAndLength(t.scratch[:0], tagAndLength{rv.Class, rv.Tag, len(rv.Bytes), rv.IsCompound, rv.IsIndefinite}))

        bodyBytes := rv.Bytes

        // it is Indefinite
        // 非定长模式
        if rv.IsIndefinite {
            bodyBytes = append(bodyBytes, []byte{0x00, 0x00}...)
        }

        t.body = bytesEncoder(bodyBytes)

        return t.encode()
    }

    switch val.Type() {
        case flagType:
            id.tag = TagBoolean
            contentsEncoder = bytesEncoder(nil)
        case timeType:
            id.tag = e.opts.timeType
            switch e.opts.timeType {
                case TagUtcTime:
                    contentsEncoder = stringEncoder(makeUTCTime(val.Interface().(time.Time)))
                default:
                    contentsEncoder = stringEncoder(makeGeneralizedTime(val.Interface().(time.Time)))
            }
        case bitStringType:
            id.tag = TagBitString
            contentsEncoder = bitStringEncoder(val.Interface().(BitString))
        case objectIdentifierType:
            id.tag = TagObjectIdentifier
            contentsEncoder = objectIdentifierEncoder(val.Interface().(ObjectIdentifier))
        case bigIntType:
            id.tag = TagInteger
            contentsEncoder, err = makeBigInt(val.Interface().(*big.Int))
            if err != nil {
                return nil, err
            }
        case nullType:
            id.tag = TagNull
            contentsEncoder = nullEncoder(val.Interface().(Null))
    }

    if contentsEncoder == nil {
        switch val.Kind() {
            case reflect.Bool:
                id.tag = TagBoolean
                contentsEncoder = boolEncoder(val.Bool())
            case reflect.String:
                id.tag = e.opts.stringType
                switch e.opts.stringType {
                    case TagPrintableString:
                        printableString, err := makePrintableString(val.String())
                        if err != nil {
                            return nil, err
                        }
                        contentsEncoder = stringEncoder(printableString)
                    case TagIa5String:
                        ia5String, err := makeIA5String(val.String())
                        if err != nil {
                            return nil, err
                        }
                        contentsEncoder = stringEncoder(ia5String)
                    case TagOctetString:
                        contentsEncoder = bytesEncoder(val.String())
                    case TagNumericString:
                        numericString, err := makeNumericString(val.String())
                        if err != nil {
                            return nil, err
                        }
                        contentsEncoder = stringEncoder(numericString)
                    default:
                        contentsEncoder = stringEncoder(val.String())
                }
            case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
                if e.opts.enumerated {
                    id.tag = TagEnumerated
                } else {
                    id.tag = TagInteger
                }
                contentsEncoder = intEncoder(val.Int())
            case reflect.Float32, reflect.Float64:
                id.tag = TagReal
                contentsEncoder = realEncoder(val.Float())
            case reflect.Struct:
                id.isConstructed = true
                if e.opts.set {
                    id.tag = TagSet
                } else {
                    id.tag = TagSequence
                }

                var encoders multiEncoder
                for i := 0; i < val.NumField(); i++ {
                    fieldVal := val.Field(i)
                    fieldStruct := val.Type().Field(i)

                    if fieldVal.CanInterface() {
                        tag := fieldStruct.Tag.Get(tagKey)
                        tagOpts, err := parseOptions(tag)
                        if err != nil {
                            return nil, err
                        }
                        fieldEncoder := NewEncoder(fieldVal.Interface(), tagOpts)
                        encoders = append(encoders, fieldEncoder)
                    }
                }
                contentsEncoder = encoders
            case reflect.Array, reflect.Slice:
                if val.Type().Elem().Kind() == reflect.Uint8 {
                    id.tag = TagOctetString
                    contentsEncoder = bytesEncoder(val.Interface().([]byte))
                } else {
                    id.isConstructed = true
                    if e.opts.set {
                        id.tag = TagSetOf
                    } else {
                        id.tag = TagSequenceOf
                    }
                    var encoders multiEncoder
                    for i := 0; i < val.Len(); i++ {
                        encoder := NewEncoder(val.Index(i).Interface(), e.opts)
                        encoders = append(encoders, encoder)
                    }
                    contentsEncoder = encoders
                }
            default:
                return nil, &UnsupportedTypeError{val.Type()}
        }
    }

    if encodedContents == nil {
        encodedContents, err = contentsEncoder.encode()

        if err != nil {
            return nil, err
        }
    }

    encodedLength := encodeLength(len(encodedContents))

    if e.opts.tag != nil {
        if e.opts.application {
            id.class = TagClassApplication
        } else if e.opts.private {
            id.class = TagClassPrivate
        } else {
            id.class = TagClassContextSpecific
        }

        if e.opts.explicit {
            if e.opts.tag == nil {
                return nil, fmt.Errorf("'explicit' flag requires 'tag' to be set")
            }

            innerId := identifier{
                class:         TagClassUniversal,
                tag:           id.tag,
                isConstructed: false,
            }

            innerBuf := new(bytes.Buffer)
            innerBuf.Write(innerId.encode())
            innerBuf.Write(encodedLength)
            innerBuf.Write(encodedContents)

            encodedContents = innerBuf.Bytes()
            encodedLength = encodeLength(len(encodedContents))

            id.isConstructed = true
        }

        // implicit
        id.tag = *e.opts.tag
    }

    encodedIdentifier := id.encode()

    e.buf.Write(encodedIdentifier)
    e.buf.Write(encodedLength)
    e.buf.Write(encodedContents)

    return e.buf.Bytes(), nil
}

type identifier struct {
    class         TagClass
    isConstructed bool
    tag           Tag
}

func (i identifier) encode() []byte {
    b := []byte{0x00}

    // class
    b[0] |= byte(i.class << 6)

    if i.isConstructed {
        b[0] |= byte(1 << 5)
    } else {
        b[0] |= byte(0 << 5)
    }

    if i.tag <= 30 {
        // short form
        b[0] |= byte(i.tag)
    } else {
        // long form
        b[0] |= byte(0x1f) // set bits 1-5 to 1
        // encoded tag in next octet
        b = append(b, encodeBase128(int(i.tag))...)
    }

    return b
}

func encodeLength(length int) []byte {
    lengthBytes := encodeUint(uint(length))

    // short form
    if length <= 0x7f {
        return lengthBytes
    }

    // long form
    b := new(bytes.Buffer)
    header := len(lengthBytes) | 0x80
    b.Write(encodeUint(uint(header)))
    b.Write(lengthBytes)

    return b.Bytes()
}

// A RawValue represents an undecoded ASN.1 object.
type RawValue struct {
    Class, Tag   int
    IsCompound   bool
    IsIndefinite bool
    Bytes        []byte
    FullBytes    []byte // includes the tag and length
}

// RawContent is used to signal that the undecoded, DER data needs to be
// preserved for a struct. To use it, the first field of the struct must have
// this type. It's an error for any of the other fields to have this type.
type RawContent []byte

// NullRawValue is a RawValue with its Tag set to the ASN.1 NULL type tag (5).
var NullRawValue = RawValue{Tag: int(TagNull)}

// NullBytes contains bytes representing the BER-encoded ASN.1 NULL type.
var NullBytes = []byte{byte(TagNull), 0}

type multiEncoder []encoder

func (m multiEncoder) length() int {
    var size int

    for _, e := range m {
        size += e.length()
    }

    return size
}

func (e multiEncoder) encode() ([]byte, error) {
    buf := new(bytes.Buffer)
    for _, encoder := range e {
        encoding, err := encoder.encode()
        if err != nil {
            return nil, err
        }
        buf.Write(encoding)
    }

    return buf.Bytes(), nil
}

type byteEncoder byte

func (c byteEncoder) length() int {
    return 1
}

func (c byteEncoder) encode() ([]byte, error) {
    return []byte{byte(c)}, nil
}

type bytesEncoder []byte

func (b bytesEncoder) length() int {
    return len(b)
}

func (e bytesEncoder) encode() ([]byte, error) {
    return e, nil
}

type taggedEncoder struct {
    // scratch contains temporary space for encoding the tag and length of
    // an element in order to avoid extra allocations.
    scratch [8]byte
    tag     encoder
    body    encoder
}

func (t *taggedEncoder) length() int {
    return t.tag.length() + t.body.length()
}

func (t *taggedEncoder) encode() ([]byte, error) {
    tagBytes, err := t.tag.encode()
    if err != nil {
        return nil, err
    }

    bodyBytes, err := t.body.encode()
    if err != nil {
        return nil, err
    }

    dst := make([]byte, 0)

    dst = append(dst, tagBytes...)
    dst = append(dst, bodyBytes...)

    return dst, nil
}

func appendTagAndLength(dst []byte, t tagAndLength) []byte {
    b := uint8(t.class) << 6
    if t.isCompound {
        b |= 0x20
    }

    if t.tag >= 31 {
        b |= 0x1f
        dst = append(dst, b)
        dst = appendBase128Int(dst, int64(t.tag))
    } else {
        b |= uint8(t.tag)
        dst = append(dst, b)
    }

    // it is Indefinite
    // 非定长模式
    if t.isIndefinite {
        dst = append(dst, byte(0x80))
    } else {
        if t.length >= 128 {
            l := lengthLength(t.length)
            dst = append(dst, 0x80|byte(l))
            dst = appendLength(dst, t.length)
        } else {
            dst = append(dst, byte(t.length))
        }
    }

    return dst
}

func appendLength(dst []byte, i int) []byte {
    n := lengthLength(i)

    for ; n > 0; n-- {
        dst = append(dst, byte(i>>uint((n-1)*8)))
    }

    return dst
}

func lengthLength(i int) (numBytes int) {
    numBytes = 1

    for i > 255 {
        numBytes++
        i >>= 8
    }

    return
}

func base128IntLength(n int64) int {
    if n == 0 {
        return 1
    }

    l := 0
    for i := n; i > 0; i >>= 7 {
        l++
    }

    return l
}

func appendBase128Int(dst []byte, n int64) []byte {
    l := base128IntLength(n)

    for i := l - 1; i >= 0; i-- {
        o := byte(n >> uint(i*7))
        o &= 0x7f
        if i != 0 {
            o |= 0x80
        }

        dst = append(dst, o)
    }

    return dst
}

func isEmpty(value reflect.Value) bool {
    if value.Type() == nullType {
        return false
    }

    defaultValue := reflect.Zero(value.Type())

    return reflect.DeepEqual(value.Interface(), defaultValue.Interface())
}

func canHaveDefaultValue(k reflect.Kind) bool {
    switch k {
        case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
            return true
    }

    return false
}
