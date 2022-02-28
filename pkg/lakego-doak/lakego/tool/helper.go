package tool

import (
    "bytes"
    "regexp"
    "errors"
    "reflect"
    "strconv"
    "strings"
    "runtime"
    "math/rand"

    "github.com/deatil/lakego-doak/lakego/router"
)

func IndexForOne(i int, p, limit int64) int64 {
    s := strconv.Itoa(i)
    index, _ := strconv.ParseInt(s, 10, 64)
    return (p-1)*limit + index + 1
}

func IndexAddOne(i interface{}) int64 {
    index, _ := ToInt64(i)
    return index + 1
}

func IndexDecrOne(i interface{}) int64 {
    index, _ := ToInt64(i)
    return index - 1
}

func StringReplace(str, old, new string) string {
    return strings.Replace(str, old, new, -1)
}

// ToString 类型转换，获得string
func ToString(v interface{}) (re string) {
    re = v.(string)
    return
}

// StringsJoin 字符串拼接
func StringsJoin(strs ...string) string {
    var str string
    var b bytes.Buffer
    strsLen := len(strs)
    if strsLen == 0 {
        return str
    }
    for i := 0; i < strsLen; i++ {
        b.WriteString(strs[i])
    }
    str = b.String()
    return str

}

// ToInt64 类型转换，获得int64
func ToInt64(v interface{}) (re int64, err error) {
    switch v.(type) {
    case string:
        re, err = strconv.ParseInt(v.(string), 10, 64)
    case float64:
        re = int64(v.(float64))
    case float32:
        re = int64(v.(float32))
    case int64:
        re = v.(int64)
    case int32:
        re = v.(int64)
    default:
        err = errors.New("不能转换")
    }
    return
}

// ToSlice 转换为数组
func ToSlice(arr interface{}) []interface{} {
    v := reflect.ValueOf(arr)
    if v.Kind() != reflect.Slice {
        panic("toslice arr not slice")
    }
    l := v.Len()
    ret := make([]interface{}, l)
    for i := 0; i < l; i++ {
        ret[i] = v.Index(i).Interface()
    }
    return ret
}

// 判断是否为 nil
func IsNil(i interface{}) bool {
    v := reflect.ValueOf(i)
    if v.Kind() != reflect.Ptr {
        return v.IsNil()
    }

    return false
}

// 生成随机数
func MakeRandomString(n int, allowedChars ...[]rune) string {
    var defaultLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    var letters []rune

    if len(allowedChars) == 0 {
        letters = defaultLetters
    } else {
        letters = allowedChars[0]
    }

    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }

    return string(b)
}

// 请求 IP
func GetRequestIp(c *router.Context) string {
    ip := c.ClientIP()

    if ip == "::1" {
        ip = "127.0.0.1"
    }

    return ip
}

// 获取 header 中指定 key 的值
func GetHeaderByName(c *router.Context, key string) string {
    return c.Request.Header.Get(key)
}

// 结构体转map
func StructToMap(obj interface{}) map[string]interface{}{
    obj1 := reflect.TypeOf(obj)
    obj2 := reflect.ValueOf(obj)

    var data = make(map[string]interface{})
    for i := 0; i < obj1.NumField(); i++ {
        data[obj1.Field(i).Name] = obj2.Field(i).Interface()
    }

    return data
}

// 反射获取名称
func GetNameFromReflect(f interface{}) string {
    t := reflect.ValueOf(f).Type()

    if t.Kind() == reflect.Func {
        return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
    }

    return t.String()
}

// 匹配链接
func MatchPath(ctx *router.Context, path string, current string) bool {
    requestPath := ctx.Request.URL.String()
    method := strings.ToUpper(ctx.Request.Method)

    if current == "" {
        current = requestPath
    }

    paths := strings.Split(path, ":")
    if len(paths) == 2 {
        methods := paths[0]
        path = paths[1]

        methods = strings.ToUpper(methods)
        methodList := strings.Split(methods, ",")
        if len(methodList) > 0 {
            if !InArray(methodList, method) {
                return false
            }
        }
    }

    if StringContains(path, "*") == -1 {
        return path == current
    }

    path = strings.Replace(path, "*", "([0-9a-zA-Z-_,:])*", -1)
    path = strings.Replace(path, "/", "\\/", -1)

    result, _ := regexp.MatchString("^" + path, current)
    if !result {
        return false
    }

    return true
}

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
