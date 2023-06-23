package asn1

import (
    "fmt"
    "unicode"
)

type stringEncoder string

func (b stringEncoder) length() int {
    return len(b)
}

func (e stringEncoder) encode() ([]byte, error) {
    return []byte(e), nil
}

type asteriskFlag bool
type ampersandFlag bool

const (
    allowAsterisk  asteriskFlag = true
    rejectAsterisk asteriskFlag = false

    allowAmpersand  ampersandFlag = true
    rejectAmpersand ampersandFlag = false
)

// isPrintable reports whether the given b is in the ASN.1 PrintableString set.
// If asterisk is allowAsterisk then '*' is also allowed, reflecting existing
// practice. If ampersand is allowAmpersand then '&' is allowed as well.
// https://en.wikipedia.org/wiki/PrintableString
func isPrintable(b byte, asterisk asteriskFlag, ampersand ampersandFlag) bool {
    return 'a' <= b && b <= 'z' ||
        'A' <= b && b <= 'Z' ||
        '0' <= b && b <= '9' ||
        '\'' <= b && b <= ')' ||
        '+' <= b && b <= '/' ||
        b == ' ' ||
        b == ':' ||
        b == '=' ||
        b == '?' ||
        // This is technically not allowed in a PrintableString.
        // However, x509 certificates with wildcard strings don't
        // always use the correct string type so we permit it.
        (bool(asterisk) && b == '*') ||
        // This is not technically allowed either. However, not
        // only is it relatively common, but there are also a
        // handful of CA certificates that contain it. At least
        // one of which will not expire until 2027.
        (bool(ampersand) && b == '&')
}

func makePrintableString(s string) (string, error) {
    stringBytes := []byte(s)
    for i := 0; i < len(stringBytes); i++ {
        if !isPrintable(stringBytes[i], allowAsterisk, allowAmpersand) {
            return "", fmt.Errorf("PrintableString contains invalid character: '%s'", string(stringBytes[i]))
        }
    }

    return s, nil
}

func makeIA5String(s string) (string, error) {
    stringBytes := []byte(s)
    for i := 0; i < len(stringBytes); i++ {
        if stringBytes[i] > 127 {
            return "", fmt.Errorf("IA5String contains invalid character: '%s'", string(stringBytes[i]))
        }
    }
    return s, nil
}

func isNumeric(b byte) bool {
    return unicode.IsDigit(rune(b)) || b == ' '
}

func makeNumericString(s string) (string, error) {
    for i := 0; i < len(s); i++ {
        if !isNumeric(s[i]) {
            return "", fmt.Errorf("NumericString contains invalid character: '%s'", string(s[i]))
        }
    }
    return s, nil
}
