package str

import (
    "fmt"
    "time"
    "html"
    "bytes"
    "regexp"
    "reflect"
    "strings"
    "strconv"
    "math/rand"
    "hash/crc32"
    "unicode"
    "unicode/utf8"
    "encoding/json"

    "github.com/iancoleman/strcase"
)

// Snake 转为 snake_case
func Snake(str string) string {
    return strcase.ToSnake(str)
}

// SnakeWithIgnore
func SnakeWithIgnore(s string, ignore string) string {
    return strcase.ToSnakeWithIgnore(s, ignore)
}

// 转为 SCREAMING_SNAKE_CASE
func ScreamingSnake(s string) string {
    return strcase.ToScreamingSnake(s)
}

// 转为 kebab-case
func Kebab(s string) string {
    return strcase.ToKebab(s)
}

// 转为 SCREAMING-KEBAB-CASE
func ScreamingKebab(s string) string {
    return strcase.ToScreamingKebab(s)
}

// 转为 delimited.snake.case
func Delimited(s string, delimiter uint8) string {
    return strcase.ToDelimited(s, delimiter)
}

// ScreamingDelimited
func ScreamingDelimited(s string, delimiter uint8, ignore string, screaming bool) string {
    return strcase.ToScreamingDelimited(s, delimiter, ignore, screaming)
}

// Camel 转为 CamelCase
func Camel(str string) string {
    return strcase.ToCamel(str)
}

// LowerCamel 转为 lowerCamelCase
func LowerCamel(str string) string {
    return strcase.ToLowerCamel(str)
}

// ==============================

// 判断位置
func Strpos(haystack string, needle string, start ...int) int {
    offset := 0
    if len(start) > 0 {
        offset = start[0]
    }

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
func Stripos(haystack string, needle string, start ...int) int {
    offset := 0
    if len(start) > 0 {
        offset = start[0]
    }

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
func Strrpos(haystack string, needle string, start ...int) int {
    offset := 0
    if len(start) > 0 {
        offset = start[0]
    }

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
func Strripos(haystack string, needle string, start ...int) int {
    offset := 0
    if len(start) > 0 {
        offset = start[0]
    }

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

// 返回字符串的子串
func Substr(str string, start int, length ...int) string {
    if len(length) == 0 {
        if start >= 0 {
            return str[start:]
        }

        return str[len(str)+start:]
    }

    newLength := length[0]

    // length 为 0 时
    if newLength == 0 {
        return ""
    }

    // length 大于 0 时
    if newLength > 0 {
        if start >= 0 {
            end := start + newLength
            if end > len(str) {
                end = len(str)
            }

            return str[start:end]
        }

        return str[len(str)+start:len(str)+start+newLength]
    }

    // length 小于 0 时
    if start >= 0 {
        end := len(str) + newLength
        if end <= 0 || start >= end {
            return ""
        }

        return str[start:end]
    }

    newStr := str[len(str)+start:]
    if len(newStr) + newLength <= 0 {
        return ""
    }

    return newStr[:len(newStr)+newLength]
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
func ToUpper(str string) string {
    return strings.ToUpper(str)
}

// 小写
func ToLower(str string) string {
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

// 非数值或字符类型的变量将会被转换成JSON格式字符串
func Strval(value interface{}) string {
    // interface 转 string
    var key string
    if value == nil {
        return ""
    }

    switch value.(type) {
        case float64:
            ft := value.(float64)
            key = strconv.FormatFloat(ft, 'f', -1, 64)
        case float32:
            ft := value.(float32)
            key = strconv.FormatFloat(float64(ft), 'f', -1, 64)
        case int:
            it := value.(int)
            key = strconv.Itoa(it)
        case uint:
            it := value.(uint)
            key = strconv.Itoa(int(it))
        case int8:
            it := value.(int8)
            key = strconv.Itoa(int(it))
        case uint8:
            it := value.(uint8)
            key = strconv.Itoa(int(it))
        case int16:
            it := value.(int16)
            key = strconv.Itoa(int(it))
        case uint16:
            it := value.(uint16)
            key = strconv.Itoa(int(it))
        case int32:
            it := value.(int32)
            key = strconv.Itoa(int(it))
        case uint32:
            it := value.(uint32)
            key = strconv.Itoa(int(it))
        case int64:
            it := value.(int64)
            key = strconv.FormatInt(it, 10)
        case uint64:
            it := value.(uint64)
            key = strconv.FormatUint(it, 10)
        case string:
            key = value.(string)
        case []byte:
            key = string(value.([]byte))
        default:
            newValue, _ := json.Marshal(value)
            key = string(newValue)
    }

    return key
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
func JSONDecode(data string, val interface{}) error {
    return json.Unmarshal([]byte(data), val)
}

// 转换为 json 字符
func JSONEncode(val interface{}) string {
    if val == nil {
        return ""
    }

    b, _ := json.Marshal(val)

    return string(b)
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

// Bindec
func Bindec(str string) (string, error) {
    i, err := strconv.ParseInt(str, 2, 0)
    if err != nil {
        return "", err
    }
    return strconv.FormatInt(i, 10), nil
}

// Hex2bin
func Hex2bin(data string) (string, error) {
    i, err := strconv.ParseInt(data, 16, 0)
    if err != nil {
        return "", err
    }
    return strconv.FormatInt(i, 2), nil
}

// Bin2hex
func Bin2hex(str string) (string, error) {
    i, err := strconv.ParseInt(str, 2, 0)
    if err != nil {
        if err.(*strconv.NumError).Err == strconv.ErrSyntax {
            byteArray := []byte(str)
            var out string
            for i := 0; i < len(byteArray); i++ {
                out += strconv.FormatInt(int64(byteArray[i]), 16)
            }

            return out, nil
        } else {
            return "", err
        }
    }

    return strconv.FormatInt(i, 16), nil
}

// 生成随机数
func Random(n int, allowedChars ...[]rune) string {
    var defaultLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    var letters []rune

    if len(allowedChars) == 0 {
        letters = defaultLetters
    } else {
        letters = allowedChars[0]
    }

    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }

    return string(b)
}

// ==============================

// 重复
func Repeat(str string, times int) string {
    return strings.Repeat(str, times)
}

// 替换
func Replace(search string, replace string, subject string) string {
    return strings.Replace(subject, search, replace, -1)
}

func ReplaceNth(s, old, new string, n int) string {
    i := 0
    for m := 1; m <= n; m++ {
        x := strings.Index(s[i:], old)
        if x < 0 {
            break
        }
        i += x
        if m == n {
            return s[:i] + new + s[i+len(old):]
        }
        i += len(old)
    }
    return s
}

// 比对
func Contains(s string, str string) int {
    return strings.Index(s, str)
}

// 最后比对
func ContainsLast(s string, str string) int {
    return strings.LastIndex(s, str)
}

// 非ASCII编码子字符
func ContainsRune(s string, ch rune) int {
    return strings.IndexRune(s, ch)
}

// 字符串拼接
func StringsJoin(strs ...string) string {
    var str string
    var b bytes.Buffer
    strsLen := len(strs)
    if strsLen == 0 {
        return str
    }

    for i := 0; i < strsLen; i++ {
        b.WriteString(strs[i])
    }

    str = b.String()
    return str
}

// 唯一 ID
func Uniqid(prefix string) string {
    now := time.Now()
    return fmt.Sprintf("%s%08x%05x", prefix, now.Unix(), now.UnixNano()%0x100000)
}

// 判断是否为空
func Empty(val interface{}) bool {
    if val == nil {
        return true
    }

    v := reflect.ValueOf(val)
    switch v.Kind() {
        case reflect.String, reflect.Array:
            return v.Len() == 0
        case reflect.Map, reflect.Slice:
            return v.Len() == 0 || v.IsNil()
        case reflect.Bool:
            return !v.Bool()
        case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
            return v.Int() == 0
        case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
            return v.Uint() == 0
        case reflect.Float32, reflect.Float64:
            return v.Float() == 0
        case reflect.Interface, reflect.Ptr:
            return v.IsNil()
    }

    return reflect.DeepEqual(val, reflect.Zero(v.Type()).Interface())
}

// 是否为 json
func IsJSON(str string) bool {
    var js json.RawMessage
    return json.Unmarshal([]byte(str), &js) == nil
}

// 判断是否为 nil
func IsNil(i interface{}) bool {
    v := reflect.ValueOf(i)
    if v.Kind() != reflect.Ptr {
        return v.IsNil()
    }

    return false
}

// 是否为数字
func IsNumeric(val interface{}) bool {
    switch val.(type) {
        case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
            return true
        case float32, float64, complex64, complex128:
            return true
        case string:
            str := val.(string)
            if str == "" {
                return false
            }

            // Trim any whitespace
            str = strings.TrimSpace(str)
            if str[0] == '-' || str[0] == '+' {
                if len(str) == 1 {
                    return false
                }
                str = str[1:]
            }

            // hex
            if len(str) > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X') {
                for _, h := range str[2:] {
                    if !((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')) {
                        return false
                    }
                }
                return true
            }

            // 0-9, Point, Scientific
            p, s, l := 0, 0, len(str)
            for i, v := range str {
                if v == '.' { // Point
                    if p > 0 || s > 0 || i+1 == l {
                        return false
                    }
                    p = i
                } else if v == 'e' || v == 'E' { // Scientific
                    if i == 0 || s > 0 || i+1 == l {
                        return false
                    }
                    s = i
                } else if v < '0' || v > '9' {
                    return false
                }
            }
            return true
    }

    return false
}

// 版本比对
func CompareVersion(src, toCompare string) bool {
    if toCompare == "" {
        return false
    }

    exp, _ := regexp.Compile(`-(.*)`)
    src = exp.ReplaceAllString(src, "")
    toCompare = exp.ReplaceAllString(toCompare, "")

    srcs := strings.Split(src, "v")
    srcArr := strings.Split(srcs[1], ".")
    op := ">"
    srcs[0] = strings.TrimSpace(srcs[0])

    list := []string{">=", "<=", "=", ">", "<"}
    for _, v := range list {
        if v == srcs[0] {
            op = srcs[0]
        }
    }

    toCompare = strings.ReplaceAll(toCompare, "v", "")

    if op == "=" {
        return srcs[1] == toCompare
    }

    if srcs[1] == toCompare && (op == "<=" || op == ">=") {
        return true
    }

    toCompareArr := strings.Split(strings.ReplaceAll(toCompare, "v", ""), ".")
    for i := 0; i < len(srcArr); i++ {
        v, err := strconv.Atoi(srcArr[i])
        if err != nil {
            return false
        }

        vv, err := strconv.Atoi(toCompareArr[i])
        if err != nil {
            return false
        }

        switch op {
            case ">", ">=":
                if v < vv {
                    return true
                } else if v > vv {
                    return false
                } else {
                    continue
                }
            case "<", "<=":
                if v > vv {
                    return true
                } else if v < vv {
                    return false
                } else {
                    continue
                }
        }
    }

    return false
}

// ==============================

// 填充字符串的两侧
func PadBoth(value string, length int, pad string) string {
    if length < 0 {
        length = 0
    }

    needLen := length - len(value)
    if needLen < 0 {
        return value
    }

    leftLen := needLen / 2

    leftData := PadLeft(value, leftLen + len(value), pad)

    newData := PadRight(leftData, length, pad)

    return newData
}

// 填充字符串的左侧
func PadLeft(value string, length int, pad string) string {
    if length < 0 {
        length = 0
    }

    needLen := length - len(value)
    if needLen < 0 {
        return value
    }

    newValue := strings.Repeat(pad, needLen)

    // 左侧取生成后的右侧字符
    value = newValue[len(newValue) - needLen:] + value

    return value
}

// 填充字符串的右侧
func PadRight(value string, length int, pad string) string {
    if length < 0 {
        length = 0
    }

    needLen := length - len(value)
    if needLen < 0 {
        return value
    }

    newValue := strings.Repeat(pad, needLen)

    value = value + newValue[:needLen]

    return value
}


