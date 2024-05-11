package bcd8421

import (
    "bytes"
    "fmt"
    "strconv"
)

func EncodeFromString(number string, bytesLength int) ([]byte, error) {
    var numberBytes []byte
    var numberLength = len(number)

    if bytesLength*2 < numberLength {
        return numberBytes, fmt.Errorf("invalid bytesLength")
    }

    nb, err := stringNumberToBytes(number)
    if err != nil {
        return numberBytes, err
    }
    if numberLength%2 == 1 {
        nb = append([]byte{0x00}, nb...)
    }
    if fill := bytesLength*2 - len(nb); fill != 0 {
        nb = append(bytes.Repeat([]byte{0x00}, fill), nb...)
    }

    for i := 0; i < len(nb); i += 2 {
        n1 := nb[i]
        n2 := nb[i+1]
        n3 := n1 << 4
        numberBytes = append(numberBytes, n3|n2)
    }

    return numberBytes, nil
}

func DecodeToString(src []byte, skipzero bool) (string, error) {
    var s string
    var foundFirst bool

    for _, b := range src {
        if b == 0x00 && !foundFirst && skipzero {
            continue
        }

        n1 := b >> 4

        mask := b << 4
        n2 := mask<<4 | mask>>4

        if n1 > 9 || n2 > 9 {
            return s, fmt.Errorf("invalid BCD 8421 bytes")
        }

        if !skipzero {
            s += strconv.Itoa(int(n1))
            s += strconv.Itoa(int(n2))
            continue
        }
        if n1 != 0x00 && !foundFirst {
            foundFirst = true
        }
        if n1 != 0x00 || foundFirst {
            s += strconv.Itoa(int(n1))
        }
        if n2 != 0x00 && !foundFirst {
            foundFirst = true
        }
        if n2 != 0x00 || foundFirst {
            s += strconv.Itoa(int(n2))
        }
    }

    return s, nil
}

func stringNumberToBytes(number string) ([]byte, error) {
    const fnAtoi = "stringNumberToBytes"

    var b []byte
    for _, ch := range []byte(number) {
        ch -= '0'
        if ch > 9 {
            return b, &strconv.NumError{
                Func: fnAtoi,
                Num: number,
                Err: strconv.ErrSyntax,
            }
        }

        b = append(b, ch)
    }

    return b, nil
}
