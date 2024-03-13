package puny

import (
    "bytes"
)

func adapt(delta int, first bool, numchars int) (bias int) {
    if first {
        delta = delta / damp
    } else {
        delta = delta / 2
    }

    delta = delta + (delta / numchars)

    k := 0
    for delta > ((baseC-tMin)*tMax)/2 {
        delta = delta / (baseC - tMin)
        k = k + baseC
    }

    bias = k + ((baseC-tMin+1)*delta)/(delta+skew)
    return
}

func codepoint2digit(r rune) int {
    switch {
        case r-48 < 10:
            return int(r - 22)
        case r-65 < 26:
            return int(r - 65)
        case r-97 < 26:
            return int(r - 97)
    }

    return baseC
}

func writeBytesDigitToCodepoint(bytes bytes.Buffer, d int) (bytes.Buffer, error) {
    var val rune
    switch {
        case d < 26:
            // 0..25 : 'a'..'z'
            val = rune(d + 'a')
        case d < 36:
            // 26..35 : '0'..'9';
            val = rune(d - 26 + '0')
        default:
            return bytes, digit2codepointErr
    }

    err := bytes.WriteByte(byte(val))
    return bytes, err
}

func writeRune(r []rune) []byte {
    str := string(r)
    return []byte(str)
}

func insert(s []rune, pos int, r rune) []rune {
    return append(s[:pos], append([]rune{r}, s[pos:]...)...)
}
