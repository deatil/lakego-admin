package array

import (
    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-array/array"
)

type (
    // Arr 别名
    Arr = array.Arr

    // Goch 别名
    Goch = goch.Goch
)

var (
    // 获取
    ArrGet = array.Get

    // 查找
    ArrFind = array.Find

    // 判断
    ArrExists = array.Exists
)

// 获取
func ArrayFrom(source any) key {
    return newKey(source)
}

// 获取
func ArrayGet(source any, key string, defVal ...any) goch.Goch {
    data := array.Get(source, key, defVal...)

    return goch.New(data)
}
