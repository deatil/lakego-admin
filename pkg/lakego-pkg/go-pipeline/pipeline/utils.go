package pipeline

import (
    "reflect"
)

type (
    // 迭代的值
    ArrayItem = any

    // 回调函数
    CallableFunc = func(any, ArrayItem) any
)

// 用回调函数迭代地将数组简化为单一的值
func ArrayReduce(array []ArrayItem, callback CallableFunc, initial any) ArrayItem {
    data := initial

    if len(array) > 0 {
        for _, item := range array {
            data = callback(data, item)
        }
    }

    return data
}

// 数组翻转
func ArrayReverse(s []any) []any {
    for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }

    return s
}

// 获取类型唯一字符串
// get TypeKey
func getTypeName(p reflect.Type) (key string) {
    for p.Kind() == reflect.Pointer {
        p = p.Elem()
        key += "*"
    }

    pkgPath := p.PkgPath()

    if pkgPath != "" {
        key += pkgPath + "."
    }

    return key + p.Name()
}

// src convert type to new typ
func convertTo(typ reflect.Type, src any) reflect.Value {
    dataKey := getTypeName(typ)

    fieldType := reflect.TypeOf(src)
    if !fieldType.ConvertibleTo(typ) {
        return reflect.New(typ).Elem()
    }

    fieldValue := reflect.ValueOf(src)

    if dataKey != getTypeName(fieldType) {
        fieldValue = fieldValue.Convert(typ)
    }

    return fieldValue
}

