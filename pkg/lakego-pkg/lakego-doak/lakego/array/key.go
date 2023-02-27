package array

import (
    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-array/array"
)

/**
 * Key
 *
 * @create 2023-2-27
 * @author deatil
 */
type Key struct {
    source any
}

// 使用
func newKey(source any) Key {
    return Key{
        source: source,
    }
}

// 获取数据
func (this Key) Value(key string, defVal ...any) goch.Goch {
    data := array.Get(this.source, key, defVal...)

    return goch.New(data)
}

// 全部
func (this Key) All() goch.Goch {
    return goch.New(this.source)
}
