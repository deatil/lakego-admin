package encode

import (
    "reflect"
    "unicode"
)

func encodeString(value reflect.Value) ([]byte, error) {
    if value.Kind() != reflect.String {
        return nil, invalidTypeError("string", value)
    }

    return []byte(value.String()), nil
}

// https://en.wikipedia.org/wiki/PrintableString
func isValidPrintableString(s string) bool {
    for _, c := range s {
        switch {
        case c >= 'a' && c <= 'z':
        case c >= 'A' && c <= 'Z':
        case c >= '0' && c <= '9':
        default:
            switch c {
            case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
            default:
                return false
            }
        }
    }
    return true
}

func isValidIA5String(s string) bool {
    for _, c := range s {
        if c > 128 {
            return false
        }
    }
    return true
}

func isValidNumericString(s string) bool {
    for _, c := range s {
        if !unicode.IsDigit(c) || c != ' ' {
            return false
        }
    }
    return true
}
