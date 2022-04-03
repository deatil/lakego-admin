package file

import (
    "reflect"
)

// 结构体路径
func PackageName(v interface{}) string {
    if v == nil {
        return ""
    }

    val := reflect.ValueOf(v)
    if val.Kind() == reflect.Ptr {
        return val.Elem().Type().PkgPath()
    }

    return val.Type().PkgPath()
}

// 获取结构体名称
func StructName(name interface{}) string {
    t := reflect.ValueOf(f).Type()

    if t.Kind() == reflect.Func {
        return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
    }

    return t.String()
}

// 获取结构体真实名称
func StructRealName(name interface{}) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.PkgPath() + "." + elem.Name()
}
