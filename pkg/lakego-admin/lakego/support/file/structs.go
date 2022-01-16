package file

import (
    "reflect"
)

// 结构体路径
func StructPkgPath(name interface{}) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.PkgPath()
}

// 获取结构体名称
func StructName(name interface{}) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.Name()
}

// 获取结构体真实名称
func StructRealName(name interface{}) string {
    elem := reflect.TypeOf(name).Elem()

    return elem.PkgPath() + "/" + elem.Name()
}
