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

// 判断是否存在
func (this key) Has(name string) bool {
    return array.Exists(this.source, name)
}

// 输出 JSON
func (this key) ToJSON() string {
    return goch.ToJSON(this.source)
}

// 输出全部
func (this key) All() goch.Goch {
    return goch.New(this.source)
}
