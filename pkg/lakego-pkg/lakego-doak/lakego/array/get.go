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

// 获取
func ArrGet(source map[string]any, key string, defVal ...any) any {
    return array.New().Get(source, key, defVal...)
}

// 获取
func ArrGetWithGoch(source map[string]any, key string, defVal ...any) Goch {
    data := array.New().Get(source, key, defVal...)

    return goch.New(data)
}
