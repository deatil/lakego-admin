package quotedprintable

import (
    "fmt"
)

func fromHex(b byte) (byte, error) {
    switch {
        case b >= '0' && b <= '9':
            return b - '0', nil
        case b >= 'A' && b <= 'F':
            return b - 'A' + 10, nil
        // Accept badly encoded bytes
        case b >= 'a' && b <= 'f':
            return b - 'a' + 10, nil
    }

    return 0, fmt.Errorf("quotedprintable: invalid quoted-printable hex byte %#02x", b)
}

func readHexByte(v []byte) (b byte, err error) {
    var hb, lb byte
    if hb, err = fromHex(v[0]); err != nil {
        return 0, err
    }

    if lb, err = fromHex(v[1]); err != nil {
        return 0, err
    }

    return hb<<4 | lb, nil
}

func isLastChar(i int, src []byte) bool {
    return i == len(src)-1 ||
        (i < len(src)-1 && src[i+1] == '\n') ||
        (i < len(src)-2 && src[i+1] == '\r' && src[i+2] == '\n')
}
