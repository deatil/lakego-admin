package path

import (
    "os"
    "strings"
    "path/filepath"
)

// 程序根目录
func BasePath() string {
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

// 格式化文件路径
func FormatPath(path string) string {
    if strings.HasPrefix(path, "{root}") {
        // 程序根目录
        basePath := BasePath()

        path = strings.TrimPrefix(path, "{root}")
        path = basePath + "/" + strings.TrimPrefix(path, "/")

        // 格式化正常重设
        newPath, err := filepath.Abs(path)
        if err == nil {
            path = newPath
        }
    }

    return path
}
