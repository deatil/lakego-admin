package helper

import (
    "io"
    "os"
    "fmt"
    "net"
    "math"
    "time"
    "bytes"
    "errors"
    "reflect"
    "strings"
    "runtime"
    "net/http"
    "archive/zip"
    "path/filepath"
    "encoding/gob"
    "encoding/binary"
)

// 包名称
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

// 复制 map
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

// 结构体转map
func StructToMap(obj interface{}) map[string]interface{} {
    obj1 := reflect.TypeOf(obj)
    obj2 := reflect.ValueOf(obj)

    var data = make(map[string]interface{})
    for i := 0; i < obj1.NumField(); i++ {
        data[obj1.Field(i).Name] = obj2.Field(i).Interface()
    }

    return data
}

// 反射获取名称
func GetNameFromReflect(f interface{}) string {
    t := reflect.ValueOf(f).Type()

    if t.Kind() == reflect.Func {
        return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
    }

    return t.String()
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

// 文件大小格式化
func FileSize(s uint64) string {
    sizes := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
    return humanateBytes(s, 1024, sizes)
}

// 时间
func TimeSince(then time.Time, m map[string]string) string {
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

        diff, diffStr = ComputeTimeDiff(diff, m)
        timeStr += ", " + diffStr
    }

    return strings.TrimPrefix(timeStr, ", ")
}

const (
    Minute = 60
    Hour   = 60 * Minute
    Day    = 24 * Hour
    Week   = 7 * Day
    Month  = 30 * Day
    Year   = 12 * Month
)

func ComputeTimeDiff(diff int64, m map[string]string) (int64, string) {
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

// 下载
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

// 解压
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

func GetHostName() (string, error) {
    return os.Hostname()
}

func GetHostByName(hostname string) (string, error) {
    ips, err := net.LookupIP(hostname)

    if ips != nil {
        for _, v := range ips {
            if v.To4() != nil {
                return v.String(), nil
            }
        }
        return "", nil
    }

    return "", err
}

func GetHostsByName(hostname string) ([]string, error) {
    ips, err := net.LookupIP(hostname)
    if ips != nil {
        var ipstrs []string
        for _, v := range ips {
            if v.To4() != nil {
                ipstrs = append(ipstrs, v.String())
            }
        }

        return ipstrs, nil
    }

    return nil, err
}

func GetHostByAddr(ipAddress string) (string, error) {
    names, err := net.LookupAddr(ipAddress)
    if names != nil {
        return strings.TrimRight(names[0], "."), nil
    }

    return "", err
}

func IP2long(ipAddress string) uint32 {
    ip := net.ParseIP(ipAddress)
    if ip == nil {
        return 0
    }
    return binary.BigEndian.Uint32(ip.To4())
}

func Long2ip(properAddress uint32) string {
    ipByte := make([]byte, 4)
    binary.BigEndian.PutUint32(ipByte, properAddress)
    ip := net.IP(ipByte)
    return ip.String()
}

// 获取环境变量
func Getenv(varname string) string {
    return os.Getenv(varname)
}

// 设置环境变量
func Putenv(setting string) error {
    s := strings.Split(setting, "=")

    if len(s) != 2 {
        return errors.New("setting: invalid")
    }

    return os.Setenv(s[0], s[1])
}

func MemoryUsage() uint64 {
    stat := new(runtime.MemStats)
    runtime.ReadMemStats(stat)
    return stat.Alloc
}

func MemoryPeakUsage() uint64 {
    stat := new(runtime.MemStats)
    runtime.ReadMemStats(stat)

    return stat.TotalAlloc
}

