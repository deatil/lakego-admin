package event

import(
    "regexp"
    "strings"
)

// 匹配检测
func MatchTypeName(typeName string, current string) bool {
    if strings.Index(typeName, "*") == -1 {
        return typeName == current
    }

    typeName = strings.Replace(typeName, "*", "([0-9a-zA-Z-_.:])*", -1)

    result, _ := regexp.MatchString("^" + typeName, current)
    if !result {
        return false
    }

    return true
}
