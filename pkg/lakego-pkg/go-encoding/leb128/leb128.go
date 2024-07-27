package leb128

// EncodeInt32 encodes the `value` as leb128 encoded byte array
func EncodeInt32(value int32) []byte {
    result := make([]byte, 0)
    val := value
    i := 0

    for {
        b := byte(val & 0x7f)
        val >>= 7
        if (val == 0 && b & 0x40 == 0) || (val == -1 && b & 0x40 != 0) {
            result = append(result, b)
            break
        }

        result = append(result, b | 0x80)
        i++
    }

    return result
}

// DecodeInt32 decodes an int32 and returns the number of bytes used from the given leb128 encoded array `value`
func DecodeInt32(value []byte) (int32, int) {
    result := uint32(0)
    shift := 0

    for _, b := range value {
        result |= uint32(b & 0x7f) << shift
        shift += 7
        if b & 0x80 == 0 {
            if shift < 32 && b & 0x40 != 0 {
                result |= ^uint32(0) << shift
            }

            break
        }
    }

    return int32(result), shift / 7
}

// EncodeInt64 encodes the `value` as leb128 encoded byte array
func EncodeInt64(value int64) []byte {
    result := make([]byte, 0)
    val := value

    for {
        b := byte(val & 0x7f)
        val >>= 7
        if (val == 0 && b & 0x40 == 0) || (val == -1 && b & 0x40 != 0) {
            result = append(result, b)
            break
        }

        result = append(result, b | 0x80)
    }

    return result
}

// DecodeInt64 decodes an int64 and returns the number of bytes used from the given leb128 encoded array `value`
func DecodeInt64(value []byte) (int64, int) {
    result := uint64(0)
    shift := 0

    for _, b := range value {
        result |= uint64(b & 0x7f) << shift
        shift += 7

        if b & 0x80 == 0 {
            if shift < 64 && b & 0x40 != 0 {
                result |= ^uint64(0) << shift
            }

            break
        }
    }

    return int64(result), shift / 7
}

// EncodeUint32 encodes the `value` as leb128 encoded byte array
func EncodeUint32(value uint32) []byte {
    result := make([]byte, 0)
    val := value

    for {
        b := byte(val & 0x7f)
        val >>= 7
        if val == 0 {
            result = append(result, b)
            break
        }

        result = append(result, b | 0x80)
    }

    return result
}

// DecodeUint32 decodes an uint32 and returns the number of bytes used from the given leb128 encoded array `value`
func DecodeUint32(value []byte) (uint32, int) {
    result := uint32(0)
    shift := 0

    for _, b := range value {
        result |= uint32(b & 0x7f) << shift
        if b & 0x80 == 0 {
            break
        }

        shift += 7
    }

    return result, shift / 7 + 1
}

// EncodeUint64 encodes the `value` as leb128 encoded byte array
func EncodeUint64(value uint64) []byte {
    result := make([]byte, 0)
    val := value

    for {
        b := byte(val & 0x7f)
        val >>= 7
        if val == 0 {
            result = append(result, b)
            break
        }

        result = append(result, b | 0x80)
    }

    return result
}

// DecodeUint64 decodes an uint64 and returns the number of bytes used from the given leb128 encoded array `value`
func DecodeUint64(value []byte) (uint64, int) {
    result := uint64(0)
    shift := 0

    for _, b := range value {
        result |= uint64(b & 0x7f) << shift
        if b & 0x80 == 0 {
            break
        }

        shift += 7
    }

    return result, shift / 7 + 1
}
