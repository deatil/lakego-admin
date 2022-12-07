package morse

import (
    "fmt"
    "strings"
)

// Decode decodes morse code in `s` using `alphabet` mapping
func Decode(s string, alphabet map[string]string, letterSeparator, wordSeparator string) (string, error) {
    res := ""
    for _, part := range strings.Split(s, letterSeparator) {
        found := false
        for key, val := range alphabet {
            if val == part {
                res += key
                found = true
                break
            }
        }
        if part == wordSeparator {
            res += " "
            found = true
        }
        if !found {
            return res, fmt.Errorf("unknown character " + part)
        }
    }
    return res, nil
}

// Encode encodes clear text in `s` using `alphabet` mapping
func Encode(s string, alphabet map[string]string, letterSeparator, wordSeparator string) string {
    res := ""
    for _, part := range s {
        p := string(part)
        if p == " " {
            if wordSeparator != "" {
                res += wordSeparator + letterSeparator
            }
        } else if morseITU[p] != "" {
            res += morseITU[p] + letterSeparator
        }
    }
    return strings.TrimSpace(res)
}

// DecodeITU translates international morse code (ITU) to text
func DecodeITU(s string) (string, error) {
    return Decode(s, morseITU, " ", "/")
}

// EncodeITU translates text to international morse code (ITU)
func EncodeITU(s string) string {
    return Encode(s, morseITU, " ", "/")
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

var (
    morseITU = map[string]string{
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
)
