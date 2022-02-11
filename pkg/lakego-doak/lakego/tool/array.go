package tool

import (
    "strings"
)


// 分解
func Explode(needle string, str string) []string {
    return strings.Split(str, needle)
}

// 合并
func Implode(needle string, str []string) string {
    return strings.Join(str, needle)
}

// 数组判断
func InArray(arr []string, str string) bool {
    for _, v := range arr {
        if v == str {
            return true
        }
    }
    return false
}
