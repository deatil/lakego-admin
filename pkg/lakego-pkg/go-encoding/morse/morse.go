package morse

import (
    "fmt"
    "unsafe"
    "reflect"
    "strings"
)

var morseITU = map[string]string{
    "a":  ".-",
    "b":  "-...",
    "c":  "-.-.",
    "d":  "-..",
    "e":  ".",
    "f":  "..-.",
    "g":  "--.",
    "h":  "....",
    "i":  "..",
    "j":  ".---",
    "k":  "-.-",
    "l":  ".-..",
    "m":  "--",
    "n":  "-.",
    "o":  "---",
    "p":  ".--.",
    "q":  "--.-",
    "r":  ".-.",
    "s":  "...",
    "t":  "-",
    "u":  "..-",
    "v":  "...-",
    "w":  ".--",
    "x":  "-..-",
    "y":  "-.--",
    "z":  "--..",
    "ä":  ".-.-",
    "ö":  "---.",
    "ü":  "..--",
    "Ch": "----",
    "0":  "-----",
    "1":  ".----",
    "2":  "..---",
    "3":  "...--",
    "4":  "....-",
    "5":  ".....",
    "6":  "-....",
    "7":  "--...",
    "8":  "---..",
    "9":  "----.",
    ".":  ".-.-.-",
    ",":  "--..--",
    "?":  "..--..",
    "!":  "..--.",
    ":":  "---...",
    "\"": ".-..-.",
    "'":  ".----.",
    "=":  "-...-",
}

// ITUEncoding is the standard morse ITU encoding.
var ITUEncoding = NewEncoding(morseITU, " ", "/")

/*
 * Encodings
 */

// An Encoding is a radix 62 encoding/decoding scheme, defined by a 62-character alphabet.
type Encoding struct {
    alphabet        map[string]string
    letterSeparator string
    wordSeparator   string
}

func NewEncoding(alphabet map[string]string, letterSeparator, wordSeparator string) *Encoding {
    e := new(Encoding)
    e.alphabet = alphabet
    e.letterSeparator = letterSeparator
    e.wordSeparator = wordSeparator

    return e
}

/*
 * Encoder
 */

// Encode encodes clear text in `s` using `alphabet` mapping
func (enc *Encoding) Encode(s []byte) []byte {
    res := ""
    for _, part := range string(s) {
        p := string(part)
        if p == " " {
            if enc.wordSeparator != "" {
                res += enc.wordSeparator + enc.letterSeparator
            }
        } else if enc.alphabet[p] != "" {
            res += enc.alphabet[p] + enc.letterSeparator
        }
    }

    return []byte(strings.TrimSpace(res))
}

// EncodeToString returns the base62 encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
    buf := enc.Encode(src)
    return string(buf)
}

/*
 * Decoder
 */

// Decode decodes morse code in `s` using `alphabet` mapping
func (enc *Encoding) Decode(s []byte) ([]byte, error) {
    res := ""
    for _, part := range strings.Split(string(s), enc.letterSeparator) {
        found := false
        for key, val := range enc.alphabet {
            if val == part {
                res += key
                found = true
                break
            }
        }

        if part == enc.wordSeparator {
            res += " "
            found = true
        }

        if !found {
            return []byte(res), fmt.Errorf("go-encoding/morse: unknown character " + part)
        }
    }

    return []byte(res), nil
}

// DecodeString returns the bytes represented by the base62 string s.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
    sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
    bh := reflect.SliceHeader{Data: sh.Data, Len: sh.Len, Cap: sh.Len}
    return enc.Decode(*(*[]byte)(unsafe.Pointer(&bh)))
}

// LooksLikeMorse returns true if string seems to be a morse encoded string
func LooksLikeMorse(s string) bool {
    if len(s) < 1 {
        return false
    }

    for _, b := range s {
        if b != '-' && b != '.' && b != ' ' {
            return false
        }
    }

    return true
}
