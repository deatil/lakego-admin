package array

import (
	"encoding/json"
	"fmt"
	"html/template"
	"reflect"
	"strconv"
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

	res, ok := toIntString(i)
	if ok {
		return res
	}

	switch s := i.(type) {
	case []byte:
		return string(s)
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
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

func toIntString(i any) (string, bool) {
	switch s := i.(type) {
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32), true
	case int:
		return strconv.Itoa(s), true
	case int64:
		return strconv.FormatInt(s, 10), true
	case int32:
		return strconv.Itoa(int(s)), true
	case int16:
		return strconv.FormatInt(int64(s), 10), true
	case int8:
		return strconv.FormatInt(int64(s), 10), true
	case uint:
		return strconv.FormatUint(uint64(s), 10), true
	case uint64:
		return strconv.FormatUint(uint64(s), 10), true
	case uint32:
		return strconv.FormatUint(uint64(s), 10), true
	case uint16:
		return strconv.FormatUint(uint64(s), 10), true
	case uint8:
		return strconv.FormatUint(uint64(s), 10), true
	}

	return "", false
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
	for !v.Type().Implements(fmtStringerType) &&
		!v.Type().Implements(errorType) &&
		v.Kind() == reflect.Ptr &&
		!v.IsNil() {
		v = v.Elem()
	}

	return v.Interface()
}

func formatPath(path []string) []any {
	p := make([]any, 0)
	for _, v := range path {
		p = append(p, v)
	}

	return p
}

func formatPathString(path []any) []string {
	p := make([]string, 0)
	for _, v := range path {
		p = append(p, toString(v))
	}

	return p
}
