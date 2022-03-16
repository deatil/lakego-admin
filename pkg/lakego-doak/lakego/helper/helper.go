package helper

import (
    "io"
    "os"
    "fmt"
    "net"
    "net/http"
    "math"
    "time"
    "bytes"
    "errors"
    "reflect"
    "strings"
    "runtime"
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
func CopyMap(m map[string]string) (map[string]string, error) {
    var buf bytes.Buffer
    enc := gob.NewEncoder(&buf)
    dec := gob.NewDecoder(&buf)
    err := enc.Encode(m)
    if err != nil {
        return map[string]string{}, err
    }

    var cm map[string]string
    err = dec.Decode(&cm)
    if err != nil {
        return map[string]string{}, err
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

func LogN(n, b float64) float64 {
    return math.Log(n) / math.Log(b)
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

