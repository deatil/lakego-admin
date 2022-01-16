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

        // 格式化为正常
        newPath, err := filepath.Abs(path)
        if err == nil {
            path = newPath
        }
    }

    return path
}

// 根目录
func RootPath(path string) string {
    rootPath := "{root}"

    if path != "" {
        rootPath = rootPath + "/" + strings.TrimSuffix(path, "/")
    }

    return FormatPath(rootPath)
}

// app 目录
func AppPath(path string) string {
    rootPath := "/app"

    if path != "" {
        rootPath = rootPath + "/" + strings.TrimSuffix(path, "/")
    }

    return RootPath(rootPath)
}

// 配置目录
func ConfigPath(path string) string {
    rootPath := "/config"

    if path != "" {
        rootPath = rootPath + "/" + strings.TrimSuffix(path, "/")
    }

    return RootPath(rootPath)
}

// 运行时目录
func RuntimePath(path string) string {
    rootPath := "/runtime"

    if path != "" {
        rootPath = rootPath + "/" + strings.TrimSuffix(path, "/")
    }

    return RootPath(rootPath)
}

// 存储目录
func StoragePath(path string) string {
    rootPath := "/storage"

    if path != "" {
        rootPath = rootPath + "/" + strings.TrimSuffix(path, "/")
    }

    return RootPath(rootPath)
}
