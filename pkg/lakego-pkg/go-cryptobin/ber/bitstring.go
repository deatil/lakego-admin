package ber

import (
    "bytes"
    "fmt"
    "math"
    "reflect"
    "strconv"
    "strings"
)

func isValidBitString(str string) bool {
    for _, c := range str {
        if !(c == '0' || c == '1') {
            return false
        }
    }
    return true
}

func EncodeBitString(value reflect.Value) ([]byte, error) {
    if value.Kind() != reflect.String {
        return nil, invalidTypeError("string", value)
    }

    bitStr := value.String()
    if !isValidBitString(bitStr) {
        return nil, fmt.Errorf("%s not a valid bit string", bitStr)
    }

    bitLen := float64(len(bitStr))
    octetBitLength := uint(8 * (math.Ceil(bitLen / 8.0)))
    unusedBits := octetBitLength - uint(bitLen)
    octetLength := octetBitLength / 8

    buf := new(bytes.Buffer)
    buf.WriteByte(byte(unusedBits))

    padding := strings.Repeat("0", int(unusedBits))
    paddedBitStr := bitStr + padding

    for i := 1; i <= int(octetLength); i++ {
        index := i * 8

        parsed, err := strconv.ParseInt(paddedBitStr[index-8:index], 2, 64)
        if err != nil {
            return nil, err
        }

        enc := encodeUint(uint64(parsed))
        buf.Write(enc)
    }

    return buf.Bytes(), nil
}
