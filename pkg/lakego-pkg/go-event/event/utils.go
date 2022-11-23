package event

import(
    "regexp"
    "reflect"
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

// 反射获取结构体名称
func GetStructName(name any) string {
    var elem reflect.Type

    nameKind := reflect.TypeOf(name).Kind()
    if nameKind == reflect.Pointer {
        elem = reflect.TypeOf(name).Elem()
    } else {
        elem = reflect.TypeOf(name)
    }

    return elem.PkgPath() + "." + elem.Name()
}

// 格式化名称
func FormatName(name any) string {
    if n, ok := name.(string); ok {
        return n
    }

    nameKind := reflect.TypeOf(name).Kind()
    if nameKind == reflect.Struct || nameKind == reflect.Pointer {
        newName := GetStructName(name)

        return newName
    }

    return ""
}
