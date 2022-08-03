package array

import (
    "fmt"
    "reflect"
    "strconv"
    "encoding/json"
    "html/template"
)

// 转为数组
func toStringMap(i any) map[string]any {
    var m = map[string]any{}

    switch v := i.(type) {
        case map[any]any:
            for k, val := range v {
                m[toString(k)] = val
            }
            return m
        case map[string]any:
            return v
        case string:
            jsonStringToObject(v, &m)
            return m
        default:
            return m
    }
}

func toString(i any) string {
    i = indirectToStringerOrError(i)

    switch s := i.(type) {
        case string:
            return s
        case bool:
            return strconv.FormatBool(s)
        case float64:
            return strconv.FormatFloat(s, 'f', -1, 64)
        case float32:
            return strconv.FormatFloat(float64(s), 'f', -1, 32)
        case int:
            return strconv.Itoa(s)
        case int64:
            return strconv.FormatInt(s, 10)
        case int32:
            return strconv.Itoa(int(s))
        case int16:
            return strconv.FormatInt(int64(s), 10)
        case int8:
            return strconv.FormatInt(int64(s), 10)
        case uint:
            return strconv.FormatUint(uint64(s), 10)
        case uint64:
            return strconv.FormatUint(uint64(s), 10)
        case uint32:
            return strconv.FormatUint(uint64(s), 10)
        case uint16:
            return strconv.FormatUint(uint64(s), 10)
        case uint8:
            return strconv.FormatUint(uint64(s), 10)
        case []byte:
            return string(s)
        case template.HTML:
            return string(s)
        case template.URL:
            return string(s)
        case template.JS:
            return string(s)
        case template.CSS:
            return string(s)
        case template.HTMLAttr:
            return string(s)
        case nil:
            return ""
        case fmt.Stringer:
            return s.String()
        case error:
            return s.Error()
        default:
            return ""
    }
}

// json 转换
func jsonStringToObject(s string, v any) error {
    data := []byte(s)
    return json.Unmarshal(data, v)
}

func indirectToStringerOrError(a any) any {
    if a == nil {
        return nil
    }

    var errorType = reflect.TypeOf((*error)(nil)).Elem()
    var fmtStringerType = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()

    v := reflect.ValueOf(a)
    for !v.Type().Implements(fmtStringerType) && !v.Type().Implements(errorType) && v.Kind() == reflect.Ptr && !v.IsNil() {
        v = v.Elem()
    }

    return v.Interface()
}
