package filesystem

import (
    "fmt"
)

// 格式化数据大小
func FormatSize(size int64) string {
    units := []string{" B", " KB", " MB", " GB", " TB", " PB"}

    s := float64(size)

    i := 0
    for ; s >= 1024 && i < len(units) - 1; i++ {
        s /= 1024
    }

    return fmt.Sprintf("%.2f%s", s, units[i])
}
