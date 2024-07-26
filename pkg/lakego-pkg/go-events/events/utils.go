package events

import (
    "reflect"
    "regexp"
    "runtime"
    "strings"
)

// 匹配检测
// match Type Name
func matchTypeName(typeName string, current string) bool {
    if strings.Index(typeName, "*") == -1 {
        return typeName == current
    }

    typeName = strings.Replace(typeName, "*", `([0-9a-zA-Z-_.:])*`, -1)

    result, _ := regexp.MatchString("^"+typeName, current)
    if !result {
        return false
    }

    return true
}

// 获取方法名称
// get Func Name
func getFuncName(data any) string {
    name := runtime.FuncForPC(reflect.ValueOf(data).Pointer()).Name()

    return name
}

// 获取类型唯一字符串
// get TypeKey
func getTypeKey(p reflect.Type) (key string) {
    if p.Kind() == reflect.Pointer {
        p = p.Elem()
        key = "*"
    }

    pkgPath := p.PkgPath()

    if pkgPath != "" {
        key += pkgPath + "."
    }

    return key + p.Name()
}

// 反射获取结构体名称
// get Struct Name
func getStructName(data any) string {
    p := reflect.TypeOf(data)

    return getTypeKey(p)
}

// 格式化名称
// format Name
func formatName(name any) string {
    if n, ok := name.(string); ok {
        return n
    }

    nameKind := reflect.TypeOf(name).Kind()
    if nameKind == reflect.Struct || nameKind == reflect.Pointer {
        return getStructName(name)
    }

    if nameKind == reflect.Func {
        return getFuncName(name)
    }

    return ""
}

// 把变量转换成反射类型
// Convert args To Types
func ConvertToTypes(args ...any) []reflect.Type {
    types := make([]reflect.Type, 0)

    for _, arg := range args {
        types = append(types, reflect.TypeOf(arg))
    }

    return types
}

// 解析结构体的tag
// Parse StructTag
func ParseStructTag(rawTag reflect.StructTag) map[string][]string {
    results := make(map[string][]string, 0)

    tags := strings.Split(string(rawTag), " ")

    for _, tagString := range tags {
        tag := strings.Split(tagString, ":")

        if len(tag) > 1 {
            tagValue := strings.ReplaceAll(tag[1], `"`, "")

            results[tag[0]] = strings.Split(tagValue, ",")
        } else {
            results[tag[0]] = nil
        }
    }

    return results
}
