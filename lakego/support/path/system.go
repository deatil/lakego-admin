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
