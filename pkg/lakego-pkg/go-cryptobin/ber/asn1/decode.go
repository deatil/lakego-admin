package asn1

import (
    "fmt"
    "time"
    "errors"
    "math"
    "math/big"
    "reflect"
    "unicode/utf8"
    "unicode/utf16"
)

// We start by dealing with each of the primitive types in turn.

// BOOLEAN

func parseBool(bytes []byte) (ret bool, err error) {
    if len(bytes) != 1 {
        err = SyntaxError{Msg: "invalid boolean"}
        return
    }

    // DER demands that "If the encoding represents the boolean value TRUE,
    // its single contents octet shall have all eight bits set to one."
    // Thus only 0 and 255 are valid encoded values.
    switch bytes[0] {
        case 0:
            ret = false
        case 0xff:
            ret = true
        default:
            err = SyntaxError{Msg: "invalid boolean"}
    }

    return
}

// INTEGER

// checkInteger returns nil if the given bytes are a valid DER-encoded
// INTEGER and an error otherwise.
func checkInteger(bytes []byte) error {
    if len(bytes) == 0 {
        return StructuralError{Msg: "empty integer"}
    }

    if len(bytes) == 1 {
        return nil
    }

    if (bytes[0] == 0 && bytes[1]&0x80 == 0) || (bytes[0] == 0xff && bytes[1]&0x80 == 0x80) {
        return StructuralError{Msg: "integer not minimally-encoded"}
    }

    return nil
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
func parseInt64(bytes []byte) (ret int64, err error) {
    err = checkInteger(bytes)
    if err != nil {
        return
    }

    if len(bytes) > 8 {
        // We'll overflow an int64 in this case.
        err = StructuralError{Msg: "integer too large"}
        return
    }

    for bytesRead := 0; bytesRead < len(bytes); bytesRead++ {
        ret <<= 8
        ret |= int64(bytes[bytesRead])
    }

    // Shift up and down in order to sign extend the result.
    ret <<= 64 - uint8(len(bytes))*8
    ret >>= 64 - uint8(len(bytes))*8
    return
}

// parseInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseInt32(bytes []byte) (int32, error) {
    if err := checkInteger(bytes); err != nil {
        return 0, err
    }

    ret64, err := parseInt64(bytes)
    if err != nil {
        return 0, err
    }

    if ret64 != int64(int32(ret64)) {
        return 0, StructuralError{Msg: "integer too large"}
    }

    return int32(ret64), nil
}

var bigOne = big.NewInt(1)

// parseBigInt treats the given bytes as a big-endian, signed integer and returns
// the result.
func parseBigInt(bytes []byte) (*big.Int, error) {
    if err := checkInteger(bytes); err != nil {
        return nil, err
    }

    ret := new(big.Int)
    if len(bytes) > 0 && bytes[0]&0x80 == 0x80 {
        // This is a negative number.
        notBytes := make([]byte, len(bytes))
        for i := range notBytes {
            notBytes[i] = ^bytes[i]
        }

        ret.SetBytes(notBytes)
        ret.Add(ret, bigOne)
        ret.Neg(ret)
        return ret, nil
    }

    ret.SetBytes(bytes)
    return ret, nil
}

// BIT STRING

// parseBitString parses an ASN.1 bit string from the given byte slice and returns it.
func parseBitString(bytes []byte) (ret BitString, err error) {
    if len(bytes) == 0 {
        err = SyntaxError{"zero length BIT STRING"}
        return
    }

    paddingBits := int(bytes[0])
    if paddingBits > 7 ||
        len(bytes) == 1 && paddingBits > 0 ||
        bytes[len(bytes)-1]&((1<<bytes[0])-1) != 0 {
        err = SyntaxError{"invalid padding bits in BIT STRING"}
        return
    }

    ret.BitLength = (len(bytes)-1)*8 - paddingBits
    ret.Bytes = bytes[1:]

    return
}

// OBJECT IDENTIFIER

// parseObjectIdentifier parses an OBJECT IDENTIFIER from the given bytes and
// returns it. An object identifier is a sequence of variable length integers
// that are assigned in a hierarchy.
func parseObjectIdentifier(bytes []byte) (s ObjectIdentifier, err error) {
    if len(bytes) == 0 {
        err = SyntaxError{Msg: "zero length OBJECT IDENTIFIER"}
        return
    }

    // In the worst case, we get two elements from the first byte (which is
    // encoded differently) and then every varint is a single byte long.
    s = make([]int, len(bytes)+1)

    // The first varint is 40*value1 + value2:
    // According to this packing, value1 can take the values 0, 1 and 2 only.
    // When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
    // then there are no restrictions on value2.
    v, offset, err := _parseBase128Int(bytes, 0)
    if err != nil {
        return
    }
    if v < 80 {
        s[0] = v / 40
        s[1] = v % 40
    } else {
        s[0] = 2
        s[1] = v - 80
    }

    i := 2
    for ; offset < len(bytes); i++ {
        v, offset, err = _parseBase128Int(bytes, offset)
        if err != nil {
            return
        }
        s[i] = v
    }

    s = s[0:i]
    return
}

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice. It returns the value and the new offset.
func parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
    offset = initOffset
    var ret64 int64
    for shifted := 0; offset < len(bytes); shifted++ {
        // 5 * 7 bits per byte == 35 bits of data
        // Thus the representation is either non-minimal or too large for an int32
        if shifted == 5 {
            err = StructuralError{Msg: "base 128 integer too large"}
            return
        }
        ret64 <<= 7
        b := bytes[offset]
        ret64 |= int64(b & 0x7f)
        offset++
        if b&0x80 == 0 {
            ret = int(ret64)
            // Ensure that the returned value fits in an int on all platforms
            if ret64 > math.MaxInt32 {
                err = StructuralError{Msg: "base 128 integer too large"}
            }
            return
        }
    }

    err = SyntaxError{Msg: "truncated base 128 integer"}
    return
}

func _parseBase128Int(bytes []byte, initOffset int) (ret, offset int, err error) {
    offset = initOffset
    for shifted := 0; offset < len(bytes); shifted++ {
        ret <<= 7
        b := bytes[offset]
        ret |= int(b & 0x7f)
        offset++
        if b&0x80 == 0 {
            return
        }
    }

    err = SyntaxError{Msg: "truncated base 128 integer"}
    return
}

// Time

// UTCTime
func parseUTCTime(bytes []byte) (ret time.Time, err error) {
    s := string(bytes)

    formatStr := "0601021504Z0700"
    ret, err = time.Parse(formatStr, s)
    if err != nil {
        formatStr = "060102150405Z0700"
        ret, err = time.Parse(formatStr, s)
    }
    if err != nil {
        return
    }

    if serialized := ret.Format(formatStr); serialized != s {
        err = fmt.Errorf("asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %q", s, serialized)
        return
    }

    if ret.Year() >= 2050 {
        // UTCTime only encodes times prior to 2050. See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
        ret = ret.AddDate(-100, 0, 0)
    }

    return
}

// parseGeneralizedTime parses the GeneralizedTime from the given byte slice
// and returns the resulting time.
func parseGeneralizedTime(bytes []byte) (ret time.Time, err error) {
    const formatStr = "20060102150405Z0700"
    s := string(bytes)

    if ret, err = time.Parse(formatStr, s); err != nil {
        return
    }

    if serialized := ret.Format(formatStr); serialized != s {
        err = fmt.Errorf("asn1: time did not serialize back to the original value and may be invalid: given %q, but serialized as %q", s, serialized)
    }

    return
}

// NumericString

// parseNumericString parses an ASN.1 NumericString from the given byte array
// and returns it.
func parseNumericString(bytes []byte) (ret string, err error) {
    for _, b := range bytes {
        if !isNumeric(b) {
            return "", SyntaxError{Msg: "NumericString contains invalid character"}
        }
    }
    return string(bytes), nil
}

// PrintableString

// parsePrintableString parses an ASN.1 PrintableString from the given byte
// array and returns it.
func parsePrintableString(bytes []byte) (ret string, err error) {
    for _, b := range bytes {
        if !isPrintable(b, allowAsterisk, allowAmpersand) {
            err = SyntaxError{Msg: "PrintableString contains invalid character"}
            return
        }
    }
    ret = string(bytes)
    return
}

// IA5String

// parseIA5String parses an ASN.1 IA5String (ASCII string) from the given
// byte slice and returns it.
func parseIA5String(bytes []byte) (ret string, err error) {
    for _, b := range bytes {
        if b >= utf8.RuneSelf {
            err = SyntaxError{Msg: "IA5String contains invalid character"}
            return
        }
    }
    ret = string(bytes)
    return
}

// parseT61String parses an ASN.1 T61String (8-bit clean string) from the given
// byte slice and returns it.
func parseT61String(bytes []byte) (ret string, err error) {
    return string(bytes), nil
}

// parseUTF8String parses an ASN.1 UTF8String (raw UTF-8) from the given byte
// array and returns it.
func parseUTF8String(bytes []byte) (ret string, err error) {
    if !utf8.Valid(bytes) {
        return "", errors.New("asn1: invalid UTF-8 string")
    }
    return string(bytes), nil
}

// parseBMPString parses an ASN.1 BMPString (Basic Multilingual Plane of
// ISO/IEC/ITU 10646-1) from the given byte slice and returns it.
func parseBMPString(bmpString []byte) (string, error) {
    if len(bmpString)%2 != 0 {
        return "", errors.New("pkcs12: odd-length BMP string")
    }

    // Strip terminator if present.
    if l := len(bmpString); l >= 2 && bmpString[l-1] == 0 && bmpString[l-2] == 0 {
        bmpString = bmpString[:l-2]
    }

    s := make([]uint16, 0, len(bmpString)/2)
    for len(bmpString) > 0 {
        s = append(s, uint16(bmpString[0])<<8+uint16(bmpString[1]))
        bmpString = bmpString[2:]
    }

    return string(utf16.Decode(s)), nil
}

// Tagging

// parseTagAndLength parses an ASN.1 tag and length pair from the given offset
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func parseTagAndLength(bytes []byte, initOffset int) (ret tagAndLength, offset int, err error) {
    offset = initOffset
    // parseTagAndLength should not be called without at least a single
    // byte to read. Thus this check is for robustness:
    if offset >= len(bytes) {
        err = errors.New("asn1: internal error in parseTagAndLength")
        return
    }

    b := bytes[offset]
    offset++

    ret.class = int(b >> 6)
    ret.isCompound = b&0x20 == 0x20
    ret.tag = int(b & 0x1f)

    // If the bottom five bits are set, then the tag number is actually base 128
    // encoded afterwards
    if ret.tag == 0x1f {
        ret.tag, offset, err = parseBase128Int(bytes, offset)
        if err != nil {
            return
        }
        // Tags should be encoded in minimal form.
        if ret.tag < 0x1f {
            err = SyntaxError{Msg: "non-minimal tag"}
            return
        }
    }

    if offset >= len(bytes) {
        err = SyntaxError{Msg: "truncated tag or length"}
        return
    }

    b = bytes[offset]
    offset++

    if b&0x80 == 0 {
        // The length is encoded in the bottom 7 bits.
        ret.length = int(b & 0x7f)
    } else {
        // Bottom 7 bits give the number of length bytes to follow.
        numBytes := int(b & 0x7f)
        if numBytes == 0 {
            if !ret.isCompound {
                err = SyntaxError{Msg: "indefinite length for non-constructed type"}
                return
            }

            ret.isIndefinite = true
            innerOffset := offset
            for innerOffset <= (len(bytes) - 2) {
                if bytes[innerOffset] == 0x00 && bytes[innerOffset+1] == 0x00 {
                    ret.length = innerOffset - offset
                    return
                }

                var t tagAndLength
                t, innerOffset, err = parseTagAndLength(bytes, innerOffset)
                if err != nil {
                    return
                }

                innerOffset += t.length
                if t.isIndefinite {
                    innerOffset += 2
                }
            }

            err = SyntaxError{Msg: "missing end-of-contents octets"}
            return
        }

        ret.length = 0
        for i := 0; i < numBytes; i++ {
            if offset >= len(bytes) {
                err = SyntaxError{Msg: "truncated tag or length"}
                return
            }

            b = bytes[offset]
            offset++

            if ret.length >= 1<<23 {
                // We can't shift ret.length up without
                // overflowing.
                err = StructuralError{Msg: "length too large"}
                return
            }

            ret.length <<= 8
            ret.length |= int(b)
        }
    }

    return
}

// SEQUENCE OF

// parseSequenceOf is used for SEQUENCE OF and SET OF values. It tries to parse
// a number of ASN.1 values from the given byte slice and returns them as a
// slice of Go values of the given type.
func parseSequenceOf(bytes []byte, sliceType reflect.Type, elemType reflect.Type) (ret reflect.Value, err error) {
    matchAny, expectedTag, compoundType, ok := getUniversalType(elemType)
    if !ok {
        err = StructuralError{Msg: "unknown Go type for slice"}
        return
    }

    // First we iterate over the input and count the number of elements,
    // checking that the types are correct in each case.
    numElements := 0
    for offset := 0; offset < len(bytes); {
        var t tagAndLength
        t, offset, err = parseTagAndLength(bytes, offset)
        if err != nil {
            return
        }

        switch t.tag {
            case tagIA5String, tagGeneralString, tagT61String, tagUTF8String, tagNumericString, tagBMPString:
                // We pretend that various other string types are
                // PRINTABLE STRINGs so that a sequence of them can be
                // parsed into a []string.
                t.tag = tagPrintableString
            case tagGeneralizedTime, tagUTCTime:
                // Likewise, both time types are treated the same.
                t.tag = tagUTCTime
        }

        if !matchAny && (t.class != classUniversal || t.isCompound != compoundType || t.tag != expectedTag) {
            err = StructuralError{Msg: "sequence tag mismatch"}
            return
        }

        if invalidLength(offset, t.length, len(bytes)) {
            err = SyntaxError{Msg: "truncated sequence"}
            return
        }

        offset += t.length
        if t.isIndefinite {
            offset += 2
        }

        numElements++
    }

    ret = reflect.MakeSlice(sliceType, numElements, numElements)
    params := fieldParameters{}

    offset := 0
    for i := 0; i < numElements; i++ {
        offset, err = parseField(ret.Index(i), bytes, offset, params)
        if err != nil {
            return
        }
    }

    return
}

var (
    enumeratedType  = reflect.TypeOf(Enumerated(0))
    flagType        = reflect.TypeOf(Flag(false))
    rawValueType    = reflect.TypeOf(RawValue{})
    rawContentsType = reflect.TypeOf(RawContent(nil))
    bigIntType      = reflect.TypeOf(new(big.Int))
)

// invalidLength reports whether offset + length > sliceLength, or if the
// addition would overflow.
func invalidLength(offset, length, sliceLength int) bool {
    return offset+length < offset || offset+length > sliceLength
}

// parseField is the main parsing function. Given a byte slice and an offset
// into the array, it will try to parse a suitable ASN.1 value out and store it
// in the given Value.
func parseField(v reflect.Value, bytes []byte, initOffset int, params fieldParameters) (offset int, err error) {
    offset = initOffset
    fieldType := v.Type()

    // If we have run out of data, it may be that there are optional elements at the end.
    if offset == len(bytes) {
        if !setDefaultValue(v, params) {
            err = SyntaxError{Msg: "sequence truncated"}
        }
        return
    }

    // Deal with the ANY type.
    if ifaceType := fieldType; ifaceType.Kind() == reflect.Interface && ifaceType.NumMethod() == 0 {
        var t tagAndLength
        t, offset, err = parseTagAndLength(bytes, offset)
        if err != nil {
            return
        }

        if invalidLength(offset, t.length, len(bytes)) {
            err = SyntaxError{Msg: "data truncated"}
            return
        }

        var result any
        if !t.isCompound && t.class == classUniversal {
            innerBytes := bytes[offset : offset+t.length]

            switch t.tag {
                case tagPrintableString:
                    result, err = parsePrintableString(innerBytes)
                case tagNumericString:
                    result, err = parseNumericString(innerBytes)
                case tagIA5String:
                    result, err = parseIA5String(innerBytes)
                case tagT61String:
                    result, err = parseT61String(innerBytes)
                case tagUTF8String:
                    result, err = parseUTF8String(innerBytes)
                case tagInteger:
                    result, err = parseInt64(innerBytes)
                case tagBitString:
                    result, err = parseBitString(innerBytes)
                case tagOID:
                    result, err = parseObjectIdentifier(innerBytes)
                case tagUTCTime:
                    result, err = parseUTCTime(innerBytes)
                case tagGeneralizedTime:
                    result, err = parseGeneralizedTime(innerBytes)
                case tagOctetString:
                    result = innerBytes
                case tagBMPString:
                    result, err = parseBMPString(innerBytes)
                default:
                    // If we don't know how to handle the type, we just leave Value as nil.
            }
        }

        offset += t.length
        if t.isIndefinite {
            offset += 2
        }

        if err != nil {
            return
        }

        if result != nil {
            v.Set(reflect.ValueOf(result))
        }

        return
    }

    t, offset, err := parseTagAndLength(bytes, offset)
    if err != nil {
        return
    }

    explicitIsIndefinite := params.explicit && t.isIndefinite
    if params.explicit {
        expectedClass := classContextSpecific
        if params.application {
            expectedClass = classApplication
        }

        if offset == len(bytes) {
            err = StructuralError{Msg: "explicit tag has no child"}
            return
        }

        if t.class == expectedClass && t.tag == *params.tag && (t.length == 0 || t.isCompound) {
            if fieldType == rawValueType {
                // The inner element should not be parsed for RawValues.
            } else if t.length > 0 {
                t, offset, err = parseTagAndLength(bytes, offset)
                if err != nil {
                    return
                }
            } else {
                if fieldType != flagType {
                    err = StructuralError{Msg: "zero length explicit tag was not an asn1.Flag"}
                    return
                }
                v.SetBool(true)
                return
            }
        } else {
            // The tags didn't match, it might be an optional element.
            ok := setDefaultValue(v, params)
            if ok {
                offset = initOffset
            } else {
                err = StructuralError{Msg: "explicitly tagged member didn't match"}
            }
            return
        }
    }

    matchAny, universalTag, compoundType, ok1 := getUniversalType(fieldType)
    if !ok1 {
        err = StructuralError{Msg: fmt.Sprintf("unknown Go type: %v", fieldType)}
        return
    }

    // Special case for strings: all the ASN.1 string types map to the Go
    // type string. getUniversalType returns the tag for PrintableString
    // when it sees a string, so if we see a different string type on the
    // wire, we change the universal type to match.
    if universalTag == tagPrintableString {
        if t.class == classUniversal {
            switch t.tag {
                case tagIA5String, tagGeneralString, tagT61String, tagUTF8String, tagNumericString, tagBMPString:
                    universalTag = t.tag
            }
        } else if params.stringType != 0 {
            universalTag = params.stringType
        }
    }

    // Special case for time: UTCTime and GeneralizedTime both map to the
    // Go type time.Time.
    if universalTag == tagUTCTime && t.tag == tagGeneralizedTime && t.class == classUniversal {
        universalTag = tagGeneralizedTime
    }

    if params.set {
        universalTag = tagSet
    }

    matchAnyClassAndTag := matchAny
    expectedClass := classUniversal
    expectedTag := universalTag

    if !params.explicit && params.tag != nil {
        expectedClass = classContextSpecific
        expectedTag = *params.tag
        matchAnyClassAndTag = false
    }

    if !params.explicit && params.application && params.tag != nil {
        expectedClass = classApplication
        expectedTag = *params.tag
        matchAnyClassAndTag = false
    }

    if !params.explicit && params.private && params.tag != nil {
        expectedClass = classPrivate
        expectedTag = *params.tag
        matchAnyClassAndTag = false
    }

    // We have unwrapped any explicit tagging at this point.
    if !matchAnyClassAndTag && (t.class != expectedClass || t.tag != expectedTag) ||
        (!matchAny && t.isCompound != compoundType) {
        // Tags don't match. Again, it could be an optional element.
        ok := setDefaultValue(v, params)
        if ok {
            offset = initOffset
        } else {
            err = StructuralError{Msg: fmt.Sprintf("tags don't match (%d vs %+v) %+v %s @%d", expectedTag, t, params, fieldType.Name(), offset)}
        }
        return
    }

    if invalidLength(offset, t.length, len(bytes)) {
        err = SyntaxError{Msg: "data truncated"}
        return
    }

    err = parseFieldContents(t, v, universalTag, bytes[initOffset:offset+t.length], offset-initOffset)
    if err != nil {
        return
    }

    offset += t.length
    if t.isIndefinite {
        offset += 2
    }

    if explicitIsIndefinite {
        offset += 2
    }

    return
}

func parseFieldContents(t tagAndLength, v reflect.Value, universalTag int, bytes []byte, offset int) (err error) {
    innerBytes := bytes[offset:]
    fieldType := v.Type()

    // We deal with the structures defined in this package first.
    switch fieldType {
        case rawValueType:
            result := RawValue{t.class, t.tag, t.isCompound, t.isIndefinite, innerBytes, bytes}
            v.Set(reflect.ValueOf(result))
            return
        case objectIdentifierType:
            newSlice, err1 := parseObjectIdentifier(innerBytes)
            v.Set(reflect.MakeSlice(v.Type(), len(newSlice), len(newSlice)))
            if err1 == nil {
                reflect.Copy(v, reflect.ValueOf(newSlice))
            }
            err = err1
            return
        case bitStringType:
            bs, err1 := parseBitString(innerBytes)
            if err1 == nil {
                v.Set(reflect.ValueOf(bs))
            }
            err = err1
            return
        case timeType:
            var time time.Time
            var err1 error
            if universalTag == tagUTCTime {
                time, err1 = parseUTCTime(innerBytes)
            } else {
                time, err1 = parseGeneralizedTime(innerBytes)
            }

            if err1 == nil {
                v.Set(reflect.ValueOf(time))
            }

            err = err1
            return
        case enumeratedType:
            parsedInt, err1 := parseInt32(innerBytes)
            if err1 == nil {
                v.SetInt(int64(parsedInt))
            }
            err = err1
            return
        case flagType:
            v.SetBool(true)
            return
        case bigIntType:
            parsedInt, err1 := parseBigInt(innerBytes)
            if err1 == nil {
                v.Set(reflect.ValueOf(parsedInt))
            }
            err = err1
            return
    }

    switch val := v; val.Kind() {
        case reflect.Bool:
            parsedBool, err1 := parseBool(innerBytes)
            if err1 == nil {
                val.SetBool(parsedBool)
            }
            err = err1
            return
        case reflect.Int, reflect.Int32, reflect.Int64:
            if val.Type().Size() == 4 {
                parsedInt, err1 := parseInt32(innerBytes)
                if err1 == nil {
                    val.SetInt(int64(parsedInt))
                }
                err = err1
            } else {
                parsedInt, err1 := parseInt64(innerBytes)
                if err1 == nil {
                    val.SetInt(parsedInt)
                }
                err = err1
            }
            return
        // TODO(dfc) Add support for the remaining integer types
        case reflect.Struct:
            structType := fieldType

            for i := 0; i < structType.NumField(); i++ {
                if structType.Field(i).PkgPath != "" {
                    err = StructuralError{Msg: "struct contains unexported fields"}
                    return
                }
            }

            if structType.NumField() > 0 &&
                structType.Field(0).Type == rawContentsType {
                val.Field(0).Set(reflect.ValueOf(RawContent(bytes)))
            }

            innerOffset := 0
            for i := 0; i < structType.NumField(); i++ {
                field := structType.Field(i)
                if i == 0 && field.Type == rawContentsType {
                    continue
                }
                innerOffset, err = parseField(val.Field(i), innerBytes, innerOffset, parseFieldParameters(field.Tag.Get("asn1")))
                if err != nil {
                    return
                }
            }
            // We allow extra bytes at the end of the SEQUENCE because
            // adding elements to the end has been used in X.509 as the
            // version numbers have increased.
            return
        case reflect.Slice:
            sliceType := fieldType
            if sliceType.Elem().Kind() == reflect.Uint8 {
                val.Set(reflect.MakeSlice(sliceType, len(innerBytes), len(innerBytes)))
                reflect.Copy(val, reflect.ValueOf(innerBytes))
                return
            }

            newSlice, err1 := parseSequenceOf(innerBytes, sliceType, sliceType.Elem())
            if err1 == nil {
                val.Set(newSlice)
            }

            err = err1
            return
        case reflect.String:
            var v string
            switch universalTag {
                case tagPrintableString:
                    v, err = parsePrintableString(innerBytes)
                case tagNumericString:
                    v, err = parseNumericString(innerBytes)
                case tagIA5String:
                    v, err = parseIA5String(innerBytes)
                case tagT61String:
                    v, err = parseT61String(innerBytes)
                case tagUTF8String:
                    v, err = parseUTF8String(innerBytes)
                case tagGeneralString:
                    // GeneralString is specified in ISO-2022/ECMA-35,
                    // A brief review suggests that it includes structures
                    // that allow the encoding to change midstring and
                    // such. We give up and pass it as an 8-bit string.
                    v, err = parseT61String(innerBytes)
                case tagBMPString:
                    v, err = parseBMPString(innerBytes)

                default:
                    err = SyntaxError{Msg: fmt.Sprintf("internal error: unknown string type %d", universalTag)}
            }

            if err == nil {
                val.SetString(v)
            }

            return
    }

    err = StructuralError{Msg: "unsupported: " + v.Type().String()}
    return
}

// setDefaultValue is used to install a default value, from a tag string, into
// a Value. It is successful if the field was optional, even if a default value
// wasn't provided or it failed to install it into the Value.
func setDefaultValue(v reflect.Value, params fieldParameters) (ok bool) {
    if !params.optional {
        return
    }

    ok = true
    if params.defaultValue == nil {
        return
    }

    if canHaveDefaultValue(v.Kind()) {
        v.SetInt(*params.defaultValue)
    }

    return
}

// Unmarshal parses the BER-encoded ASN.1 data structure b
// and uses the reflect package to fill in an arbitrary value pointed at by val.
// Because Unmarshal uses the reflect package, the structs
// being written to must use upper case field names.
//
// An ASN.1 INTEGER can be written to an int, int32, int64,
// or *big.Int (from the math/big package).
// If the encoded value does not fit in the Go type,
// Unmarshal returns a parse error.
//
// An ASN.1 BIT STRING can be written to a BitString.
//
// An ASN.1 OCTET STRING can be written to a []byte.
//
// An ASN.1 OBJECT IDENTIFIER can be written to an
// ObjectIdentifier.
//
// An ASN.1 ENUMERATED can be written to an Enumerated.
//
// An ASN.1 UTCTIME or GENERALIZEDTIME can be written to a time.Time.
//
// An ASN.1 PrintableString, IA5String, or NumericString can be written to a string.
//
// Any of the above ASN.1 values can be written to an any.
// The value stored in the interface has the corresponding Go type.
// For integers, that type is int64.
//
// An ASN.1 SEQUENCE OF x or SET OF x can be written
// to a slice if an x can be written to the slice's element type.
//
// An ASN.1 SEQUENCE or SET can be written to a struct
// if each of the elements in the sequence can be
// written to the corresponding element in the struct.
//
// The following tags on struct fields have special meaning to Unmarshal:
//
//	application specifies that an APPLICATION tag is used
//	private     specifies that a PRIVATE tag is used
//	default:x   sets the default value for optional integer fields (only used if optional is also present)
//	explicit    specifies that an additional, explicit tag wraps the implicit one
//	optional    marks the field as ASN.1 OPTIONAL
//	set         causes a SET, rather than a SEQUENCE type to be expected
//	tag:x       specifies the ASN.1 tag number; implies ASN.1 CONTEXT SPECIFIC
//
// If the type of the first field of a structure is RawContent then the raw
// ASN1 contents of the struct will be stored in it.
//
// If the type name of a slice element ends with "SET" then it's treated as if
// the "set" tag was set on it. This can be used with nested slices where a
// struct tag cannot be given.
//
// Other ASN.1 types are not supported; if it encounters them,
// Unmarshal returns a parse error.
func Unmarshal(b []byte, val any) (rest []byte, err error) {
    return UnmarshalWithParams(b, val, "")
}

// UnmarshalWithParams allows field parameters to be specified for the
// top-level element. The form of the params is the same as the field tags.
func UnmarshalWithParams(b []byte, val any, params string) (rest []byte, err error) {
    v := reflect.ValueOf(val).Elem()

    offset, err := parseField(v, b, 0, parseFieldParameters(params))
    if err != nil {
        return nil, err
    }

    return b[offset:], nil
}
