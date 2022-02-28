package str

import (
    "time"
    "html"
    "bytes"
    "strings"
    "math/rand"
    "hash/crc32"
    "unicode"
    "unicode/utf8"
    "encoding/json"
)

// 判断位置
func Strpos(haystack string, needle string, offset int) int {
    length := len(haystack)
    if length == 0 || offset > length || -offset > length {
        return -1
    }

    if offset < 0 {
        offset += length
    }

    pos := strings.Index(haystack[offset:], needle)
    if pos == -1 {
        return -1
    }

    return pos + offset
}

// 判断位置
func Stripos(haystack string, needle string, offset int) int {
    length := len(haystack)
    if length == 0 || offset > length || -offset > length {
        return -1
    }

    haystack = haystack[offset:]
    if offset < 0 {
        offset += length
    }

    pos := strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
    if pos == -1 {
        return -1
    }

    return pos + offset
}

// Strrpos
func Strrpos(haystack string, needle string, offset int) int {
    pos, length := 0, len(haystack)
    if length == 0 || offset > length || -offset > length {
        return -1
    }

    if offset < 0 {
        haystack = haystack[:offset+length+1]
    } else {
        haystack = haystack[offset:]
    }

    pos = strings.LastIndex(haystack, needle)
    if offset > 0 && pos != -1 {
        pos += offset
    }

    return pos
}

// Strripos
func Strripos(haystack string, needle string, offset int) int {
    pos, length := 0, len(haystack)
    if length == 0 || offset > length || -offset > length {
        return -1
    }

    if offset < 0 {
        haystack = haystack[:offset+length+1]
    } else {
        haystack = haystack[offset:]
    }

    pos = strings.LastIndex(strings.ToLower(haystack), strings.ToLower(needle))
    if offset > 0 && pos != -1 {
        pos += offset
    }

    return pos
}

// Ucfirst
func Ucfirst(str string) string {
    for _, v := range str {
        u := string(unicode.ToUpper(v))
        return u + str[len(u):]
    }

    return ""
}

// Lcfirst
func Lcfirst(str string) string {
    for _, v := range str {
        u := string(unicode.ToLower(v))
        return u + str[len(u):]
    }

    return ""
}

// Ucwords
func Ucwords(str string) string {
    return strings.Title(str)
}

// Substr
func Substr(str string, start uint, length int) string {
    if start < 0 || length < -1 {
        return str
    }

    switch {
        case length == -1:
            return str[start:]
        case length == 0:
            return ""
    }

    end := int(start) + length
    if end > len(str) {
        end = len(str)
    }

    return str[start:end]
}

// Strrev
func Strrev(str string) string {
    runes := []rune(str)

    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }

    return string(runes)
}

// StrWordCount
func StrWordCount(str string) []string {
    return strings.Fields(str)
}

// Strlen
func Strlen(str string) int {
    return len(str)
}

// MbStrlen
func MbStrlen(str string) int {
    return utf8.RuneCountInString(str)
}

// 大写
func StrToUpper(str string) string {
    return strings.ToUpper(str)
}

// 小写
func StrToLower(str string) string {
    return strings.ToLower(str)
}

// Strstr
func Strstr(haystack string, needle string) string {
    if needle == "" {
        return ""
    }

    idx := strings.Index(haystack, needle)
    if idx == -1 {
        return ""
    }

    return haystack[idx+len([]byte(needle))-1:]
}

// Strtr("baab", "ab", "01") will return "1001", a => 0; b => 1.
func Strtr(haystack string, params ...interface{}) string {
    ac := len(params)
    if ac == 1 {
        pairs := params[0].(map[string]string)
        length := len(pairs)
        if length == 0 {
            return haystack
        }

        oldnew := make([]string, length*2)
        for o, n := range pairs {
            if o == "" {
                return haystack
            }
            oldnew = append(oldnew, o, n)
        }

        return strings.NewReplacer(oldnew...).Replace(haystack)
    } else if ac == 2 {
        from := params[0].(string)
        to := params[1].(string)

        trlen, lt := len(from), len(to)
        if trlen > lt {
            trlen = lt
        }
        if trlen == 0 {
            return haystack
        }

        str := make([]uint8, len(haystack))
        var xlat [256]uint8
        var i int
        var j uint8

        if trlen == 1 {
            for i = 0; i < len(haystack); i++ {
                if haystack[i] == from[0] {
                    str[i] = to[0]
                } else {
                    str[i] = haystack[i]
                }
            }
            return string(str)
        }

        // trlen != 1
        for {
            xlat[j] = j
            if j++; j == 0 {
                break
            }
        }

        for i = 0; i < trlen; i++ {
            xlat[from[i]] = to[i]
        }

        for i = 0; i < len(haystack); i++ {
            str[i] = xlat[haystack[i]]
        }

        return string(str)
    }

    return haystack
}

// StrShuffle
func StrShuffle(str string) string {
    runes := []rune(str)
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    s := make([]rune, len(runes))

    for i, v := range r.Perm(len(runes)) {
        s[i] = runes[v]
    }

    return string(s)
}

// Explode
func Explode(delimiter, str string) []string {
    return strings.Split(str, delimiter)
}

// Chr
func Chr(ascii int) string {
    return string(ascii)
}

// Ord
func Ord(char string) int {
    r, _ := utf8.DecodeRune([]byte(char))
    return int(r)
}

// Nl2br
// \n\r, \r\n, \r, \n
func Nl2br(str string, isXhtml bool) string {
    r, n, runes := '\r', '\n', []rune(str)
    var br []byte

    if isXhtml {
        br = []byte("<br />")
    } else {
        br = []byte("<br>")
    }

    skip := false
    length := len(runes)
    var buf bytes.Buffer
    for i, v := range runes {
        if skip {
            skip = false
            continue
        }

        switch v {
            case n, r:
                if (i+1 < length) && (v == r && runes[i+1] == n) || (v == n && runes[i+1] == r) {
                    buf.Write(br)
                    skip = true
                    continue
                }

                buf.Write(br)
            default:
                buf.WriteRune(v)
        }
    }

    return buf.String()
}

// JSONDecode
func JSONDecode(data []byte, val interface{}) error {
    return json.Unmarshal(data, val)
}

// JSONEncode
func JSONEncode(val interface{}) ([]byte, error) {
    return json.Marshal(val)
}

// Addslashes
func Addslashes(str string) string {
    var buf bytes.Buffer

    for _, char := range str {
        switch char {
            case '\'', '"', '\\':
                buf.WriteRune('\\')
        }

        buf.WriteRune(char)
    }

    return buf.String()
}

// Stripslashes
func Stripslashes(str string) string {
    var buf bytes.Buffer

    l, skip := len(str), false
    for i, char := range str {
        if skip {
            skip = false
        } else if char == '\\' {
            if i+1 < l && str[i+1] == '\\' {
                skip = true
            }
            continue
        }

        buf.WriteRune(char)
    }

    return buf.String()
}

// Htmlentities
func Htmlentities(str string) string {
    return html.EscapeString(str)
}

// HTMLEntityDecode
func HTMLEntityDecode(str string) string {
    return html.UnescapeString(str)
}

// Crc32
func Crc32(str string) uint32 {
    return crc32.ChecksumIEEE([]byte(str))
}

