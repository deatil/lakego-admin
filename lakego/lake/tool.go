package lake

import (
    "bytes"
    "fmt"
    "io"
    "math"
    "os"
    "reflect"
    "regexp"
    "strconv"
    "strings"
    "time"
    "net/http"
    "net/url"
    "path/filepath"
    "encoding/gob"
    "encoding/json"
    "archive/zip"
)

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

func WrapURL(u string) string {
    uarr := strings.Split(u, "?")
    if len(uarr) < 2 {
        return url.QueryEscape(strings.ReplaceAll(u, "/", "_"))
    }
    v, err := url.ParseQuery(uarr[1])
    if err != nil {
        return url.QueryEscape(strings.ReplaceAll(u, "/", "_"))
    }
    return url.QueryEscape(strings.ReplaceAll(uarr[0], "/", "_")) + "?" +
        strings.ReplaceAll(v.Encode(), "%7B%7B.Id%7D%7D", "{{.Id}}")
}

func IsJSON(str string) bool {
    var js json.RawMessage
    return json.Unmarshal([]byte(str), &js) == nil
}

func JSON(a interface{}) string {
    if a == nil {
        return ""
    }
    b, _ := json.Marshal(a)
    return string(b)
}

func ParseBool(s string) bool {
    b1, _ := strconv.ParseBool(s)
    return b1
}

func ReplaceAll(s string, oldnew ...string) string {
    repl := strings.NewReplacer(oldnew...)
    return repl.Replace(s)
}

func StringContains(s string, str string) int {
    return strings.Index(s, str)
}

func StringLastContains(s string, str string) int {
    return strings.LastIndex(s, str)
}

// 非ASCII编码子字符
func StringRuneContains(s string, ch rune) int {
    return strings.IndexRune(s, ch)
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

func PackageName(v interface{}) string {
    if v == nil {
        return ""
    }

    val := reflect.ValueOf(v)
    if val.Kind() == reflect.Ptr {
        return val.Elem().Type().PkgPath()
    }
    return val.Type().PkgPath()
}

func ParseFloat32(f string) float32 {
    s, _ := strconv.ParseFloat(f, 32)
    return float32(s)
}

func SetDefault(value, condition, def string) string {
    if value == condition {
        return def
    }
    return value
}

func AorB(condition bool, a, b string) string {
    if condition {
        return a
    }
    return b
}

func CopyMap(m map[string]string) map[string]string {
    var buf bytes.Buffer
    enc := gob.NewEncoder(&buf)
    dec := gob.NewDecoder(&buf)
    err := enc.Encode(m)
    if err != nil {
        panic(err)
    }
    var cm map[string]string
    err = dec.Decode(&cm)
    if err != nil {
        panic(err)
    }
    return cm
}

func ParseTime(stringTime string) time.Time {
    loc, _ := time.LoadLocation("Local")
    theTime, _ := time.ParseInLocation("2006-01-02 15:04:05", stringTime, loc)
    return theTime
}

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
    if InArray([]string{">=", "<=", "=", ">", "<"}, srcs[0]) {
        op = srcs[0]
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

const (
    Byte  = 1
    KByte = Byte * 1024
    MByte = KByte * 1024
    GByte = MByte * 1024
    TByte = GByte * 1024
    PByte = TByte * 1024
    EByte = PByte * 1024
)

func logn(n, b float64) float64 {
    return math.Log(n) / math.Log(b)
}

func humanateBytes(s uint64, base float64, sizes []string) string {
    if s < 10 {
        return fmt.Sprintf("%d B", s)
    }
    e := math.Floor(logn(float64(s), base))
    suffix := sizes[int(e)]
    val := float64(s) / math.Pow(base, math.Floor(e))
    f := "%.0f"
    if val < 10 {
        f = "%.1f"
    }

    return fmt.Sprintf(f+" %s", val, suffix)
}

// FileSize calculates the file size and generate user-friendly string.
func FileSize(s uint64) string {
    sizes := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
    return humanateBytes(s, 1024, sizes)
}

func FileExist(path string) bool {
    _, err := os.Stat(path)
    if err != nil {
        return os.IsExist(err)
    }
    return true
}

// TimeSincePro calculates the time interval and generate full user-friendly string.
func TimeSincePro(then time.Time, m map[string]string) string {
    now := time.Now()
    diff := now.Unix() - then.Unix()

    if then.After(now) {
        return "future"
    }

    var timeStr, diffStr string
    for {
        if diff == 0 {
            break
        }

        diff, diffStr = computeTimeDiff(diff, m)
        timeStr += ", " + diffStr
    }
    return strings.TrimPrefix(timeStr, ", ")
}

// Seconds-based time units
const (
    Minute = 60
    Hour   = 60 * Minute
    Day    = 24 * Hour
    Week   = 7 * Day
    Month  = 30 * Day
    Year   = 12 * Month
)

func computeTimeDiff(diff int64, m map[string]string) (int64, string) {
    diffStr := ""
    switch {
    case diff <= 0:
        diff = 0
        diffStr = "now"
    case diff < 2:
        diff = 0
        diffStr = "1 " + m["second"]
    case diff < 1*Minute:
        diffStr = fmt.Sprintf("%d "+m["seconds"], diff)
        diff = 0

    case diff < 2*Minute:
        diff -= 1 * Minute
        diffStr = "1 " + m["minute"]
    case diff < 1*Hour:
        diffStr = fmt.Sprintf("%d "+m["minutes"], diff/Minute)
        diff -= diff / Minute * Minute

    case diff < 2*Hour:
        diff -= 1 * Hour
        diffStr = "1 " + m["hour"]
    case diff < 1*Day:
        diffStr = fmt.Sprintf("%d "+m["hours"], diff/Hour)
        diff -= diff / Hour * Hour

    case diff < 2*Day:
        diff -= 1 * Day
        diffStr = "1 " + m["day"]
    case diff < 1*Week:
        diffStr = fmt.Sprintf("%d "+m["days"], diff/Day)
        diff -= diff / Day * Day

    case diff < 2*Week:
        diff -= 1 * Week
        diffStr = "1 " + m["week"]
    case diff < 1*Month:
        diffStr = fmt.Sprintf("%d "+m["weeks"], diff/Week)
        diff -= diff / Week * Week

    case diff < 2*Month:
        diff -= 1 * Month
        diffStr = "1 " + m["month"]
    case diff < 1*Year:
        diffStr = fmt.Sprintf("%d "+m["months"], diff/Month)
        diff -= diff / Month * Month

    case diff < 2*Year:
        diff -= 1 * Year
        diffStr = "1 " + m["year"]
    default:
        diffStr = fmt.Sprintf("%d "+m["years"], diff/Year)
        diff = 0
    }
    return diff, diffStr
}

func DownloadTo(url, output string) error {

    req, err := http.NewRequest("GET", url, nil)

    if err != nil {
        return err
    }

    res, err := http.DefaultClient.Do(req)

    if err != nil {
        return err
    }

    defer func() {
        _ = res.Body.Close()
    }()

    file, err := os.Create(output)

    if err != nil {
        return err
    }

    _, err = io.Copy(file, res.Body)

    if err != nil {
        return err
    }

    return nil
}

func UnzipDir(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil {
        return err
    }
    defer func() {
        if err := r.Close(); err != nil {
            panic(err)
        }
    }()

    err = os.MkdirAll(dest, 0750)

    if err != nil {
        return err
    }

    // Closure to address file descriptors issue with all the deferred .Close() methods
    extractAndWriteFile := func(f *zip.File) error {
        rc, err := f.Open()
        if err != nil {
            return err
        }
        defer func() {
            if err := rc.Close(); err != nil {
                panic(err)
            }
        }()

        path := filepath.Join(dest, f.Name)

        if f.FileInfo().IsDir() {
            err = os.MkdirAll(path, f.Mode())
            if err != nil {
                return err
            }
        } else {
            err = os.MkdirAll(filepath.Dir(path), f.Mode())
            if err != nil {
                return err
            }
            f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
            if err != nil {
                return err
            }
            defer func() {
                if err := f.Close(); err != nil {
                    panic(err)
                }
            }()

            _, err = io.Copy(f, rc)
            if err != nil {
                return err
            }
        }
        return nil
    }

    for _, f := range r.File {
        err := extractAndWriteFile(f)
        if err != nil {
            return err
        }
    }

    return nil
}
