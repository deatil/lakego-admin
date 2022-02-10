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

        basePath, _ = filepath.Abs(basePath)
    } else {
        basePath = ""
    }

    return basePath
}

// 格式化文件路径
func formatPath(path string) string {
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

// normalizePath
func normalizePath(rootPath string, path string) string {
    if path != "" {
        newPath := rootPath + "/" + strings.TrimSuffix(path, "/")

        return newPath
    }

    return rootPath
}

// 根目录
func RootPath(path string) string {
    newPath := normalizePath("{root}", path)

    return formatPath(newPath)
}

// app 目录
func AppPath(path string) string {
    newPath := normalizePath("/app", path)

    return RootPath(newPath)
}

// 配置目录
func ConfigPath(path string) string {
    newPath := normalizePath("/config", path)

    return RootPath(newPath)
}

// 资源目录
func ResourcesPath(path string) string {
    newPath := normalizePath("/resources", path)

    return RootPath(newPath)
}

// 运行时目录
func RuntimePath(path string) string {
    newPath := normalizePath("/runtime", path)

    return RootPath(newPath)
}

// 存储目录
func StoragePath(path string) string {
    newPath := normalizePath("/storage", path)

    return RootPath(newPath)
}

// 对外目录
func PublicPath(path string) string {
    newPath := normalizePath("/public", path)

    return RootPath(newPath)
}

// 格式化文件路径
func FormatPath(path string) string {
    if strings.HasPrefix(path, "{root}") {
        path = strings.TrimPrefix(path, "{root}")
        path = RootPath(path)

    } else if strings.HasPrefix(path, "{app}") {
        path = strings.TrimPrefix(path, "{app}")
        path = AppPath(path)

    } else if strings.HasPrefix(path, "{config}") {
        path = strings.TrimPrefix(path, "{config}")
        path = ConfigPath(path)

    } else if strings.HasPrefix(path, "{runtime}") {
        path = strings.TrimPrefix(path, "{runtime}")
        path = RuntimePath(path)

    } else if strings.HasPrefix(path, "{resources}") {
        path = strings.TrimPrefix(path, "{resources}")
        path = ResourcesPath(path)

    } else if strings.HasPrefix(path, "{storage}") {
        path = strings.TrimPrefix(path, "{storage}")
        path = StoragePath(path)

    } else if strings.HasPrefix(path, "{public}") {
        path = strings.TrimPrefix(path, "{public}")
        path = PublicPath(path)

    }

    return path
}
