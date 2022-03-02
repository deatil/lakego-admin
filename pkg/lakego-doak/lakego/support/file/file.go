package file

import (
    "os"
    "fmt"
    "log"
    "strings"
    "path/filepath"
)

// 执行文件绝对路径
func SelfPath() string {
    pt, _ := filepath.Abs(os.Args[0])
    return pt
}

// 执行文件爱你目录
func SelfDir() string {
    return filepath.Dir(SelfPath())
}

// 创建文件夹
func InsureDir(path string) error {
    _, err := os.Stat(path)
    if err == nil || os.IsExist(err) {
        return nil
    }

    return os.MkdirAll(path, os.ModePerm)
}

// 创建文件夹
func EnsureDir(fp string) error {
    return os.MkdirAll(fp, os.ModePerm)
}

// 在目录里搜索文件
func SearchFile(filename string, paths ...string) (fullPath string, err error) {
    for _, pt := range paths {
        fullPath = filepath.Join(pt, filename)

        _, err = os.Stat(fullPath)
        if err == nil || os.IsExist(err) {
            return
        }
    }

    err = fmt.Errorf("%s not found in paths", fullPath)
    return
}

// 打开文件
func MustOpenFile(fp string) *os.File {
    if strings.Contains(fp, "/") || strings.Contains(fp, "\\") {
        dir := filepath.Dir(fp)
        err := EnsureDir(dir)
        if err != nil {
            log.Fatalf("mkdir -p %s occur error %v", dir, err)
        }
    }

    f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("open %s occur error %v", fp, err)
    }

    return f
}

// 写入文件
func WriteFile(filename string, contents string, flag ...int) (int, error) {
    // os.O_CREATE|os.O_RDWR|os.O_APPEND
    newFlag := os.O_CREATE|os.O_WRONLY
    if len(flag) > 0 {
        newFlag = flag[0]
    }

    data := []byte(contents)

    // 创建文件夹
    InsureDir(filepath.Dir(filename))

    fl, err := os.OpenFile(filename, newFlag, 0666)
    if err != nil {
        return 0, err
    }

    defer fl.Close()

    return fl.Write(data)
}

// 格式化数据大小
func FormatBytes(size int64) string {
    units := []string{" B", " KB", " MB", " GB", " TB", " PB"}

    s := float64(size)

    i := 0
    for ; s >= 1024 && i < 5; i++ {
        s /= 1024
    }

    return fmt.Sprintf("%.2f%s", s, units[i])
}

