package path

import (
    "os"
    "strings"
)

// 程序根目录
func GetBasePath() string {
    var basePath string

    if path, err := os.Getwd(); err == nil {
        // 路径进行处理，兼容单元测试程序程序启动时的奇怪路径
        if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-test") {
            basePath = strings.Replace(strings.Replace(path, `\test`, "", 1), `/test`, "", 1)
        } else {
            basePath = path
        }
    } else {
        basePath = ""
    }

    return basePath
}

// 配置目录
func GetConfigPath() string {
    return GetBasePath() + "/config"
}

// 判断所给路径是否为文件夹
func IsDir(path string) bool {
    s, err := os.Stat(path)
    if err != nil {
        return false
    }
    return s.IsDir()
}

// 判断所给路径是否为文件
func IsFile(path string) bool {
    return !IsDir(path)
}

// 创建文件夹
func MakeDir(str string) error {
    err := os.MkdirAll(str, 0755)
    if err != nil {
        return err
    }

    return nil
}

// 判断是否存在
func Exists(path string) bool {
    _, err := os.Stat(path)
    if err == nil {
        return true
    }

    if os.IsExist(err) {
        return true
    }

    return false
}

// 删除文件，参数文件路径
func RemoveFile(path string) error {
    //删除文件
    err := os.Remove(path)
    if err != nil {
        return err
    }

    return nil
}
