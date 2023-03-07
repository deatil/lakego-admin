package array

import (
    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-array/array"
)

/**
 * key
 *
 * @create 2023-2-27
 * @author deatil
 */
type key struct {
    source any
}

// 使用
func newKey(source any) key {
    return key{
        source: source,
    }
}

// 获取数据
func (this key) Value(name string, defVal ...any) goch.Goch {
    data := array.Get(this.source, name, defVal...)

    return goch.New(data)
}

// 全部
func (this key) All() goch.Goch {
    return goch.New(this.source)
}
