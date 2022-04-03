package str

import (
    "regexp"
    "strconv"
    "reflect"
    "strings"
)

// 判断是否为空
func Empty(val interface{}) bool {
    if val == nil {
        return true
    }

    v := reflect.ValueOf(val)
    switch v.Kind() {
        case reflect.String, reflect.Array:
            return v.Len() == 0
        case reflect.Map, reflect.Slice:
            return v.Len() == 0 || v.IsNil()
        case reflect.Bool:
            return !v.Bool()
        case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
            return v.Int() == 0
        case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
            return v.Uint() == 0
        case reflect.Float32, reflect.Float64:
            return v.Float() == 0
        case reflect.Interface, reflect.Ptr:
            return v.IsNil()
    }

    return reflect.DeepEqual(val, reflect.Zero(v.Type()).Interface())
}

// 判断是否为 nil
func IsNil(i interface{}) bool {
    v := reflect.ValueOf(i)
    if v.Kind() != reflect.Ptr {
        return v.IsNil()
    }

    return false
}

// 是否为数字
func IsNumeric(val interface{}) bool {
    switch val.(type) {
        case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
            return true
        case float32, float64, complex64, complex128:
            return true
        case string:
            str := val.(string)
            if str == "" {
                return false
            }

            // Trim any whitespace
            str = strings.TrimSpace(str)
            if str[0] == '-' || str[0] == '+' {
                if len(str) == 1 {
                    return false
                }
                str = str[1:]
            }

            // hex
            if len(str) > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X') {
                for _, h := range str[2:] {
                    if !((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')) {
                        return false
                    }
                }
                return true
            }

            // 0-9, Point, Scientific
            p, s, l := 0, 0, len(str)
            for i, v := range str {
                if v == '.' { // Point
                    if p > 0 || s > 0 || i+1 == l {
                        return false
                    }
                    p = i
                } else if v == 'e' || v == 'E' { // Scientific
                    if i == 0 || s > 0 || i+1 == l {
                        return false
                    }
                    s = i
                } else if v < '0' || v > '9' {
                    return false
                }
            }
            return true
    }

    return false
}

// 版本比对
func CompareVersion(src, toCompare string) bool {
    if toCompare == "" {
        return false
    }

    exp, _ := regexp.Compile(`-(.*)`)
    src = exp.ReplaceAllString(src, "")
    toCompare = exp.ReplaceAllString(toCompare, "")

    srcs := strings.Split(src, "v")
    srcArr := strings.Split(srcs[1], ".")
    op := ">"
    srcs[0] = strings.TrimSpace(srcs[0])

    list := []string{">=", "<=", "=", ">", "<"}
    for _, v := range list {
        if v == srcs[0] {
            op = srcs[0]
        }
    }

    toCompare = strings.ReplaceAll(toCompare, "v", "")

    if op == "=" {
        return srcs[1] == toCompare
    }

    if srcs[1] == toCompare && (op == "<=" || op == ">=") {
        return true
    }

    toCompareArr := strings.Split(strings.ReplaceAll(toCompare, "v", ""), ".")
    for i := 0; i < len(srcArr); i++ {
        v, err := strconv.Atoi(srcArr[i])
        if err != nil {
            return false
        }

        vv, err := strconv.Atoi(toCompareArr[i])
        if err != nil {
            return false
        }

        switch op {
            case ">", ">=":
                if v < vv {
                    return true
                } else if v > vv {
                    return false
                } else {
                    continue
                }
            case "<", "<=":
                if v > vv {
                    return true
                } else if v < vv {
                    return false
                } else {
                    continue
                }
        }
    }

    return false
}
