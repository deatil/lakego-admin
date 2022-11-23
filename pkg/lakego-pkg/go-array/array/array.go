package array

import (
    "reflect"
    "strconv"
    "strings"
)

/**
 * 获取数组数据
 *
 * @create 2022-5-3
 * @author deatil
 */
type Arr struct {
    // 分隔符
    keyDelim string
}

// 设置 keyDelim
func (this Arr) WithKeyDelim(data string) Arr {
    this.keyDelim = data

    return this
}

// 判断是否存在
func (this Arr) Exists(source map[string]any, key string) bool {
    if this.Find(source, key) != nil {
        return true
    }

    return false
}

// 获取
func (this Arr) Get(source map[string]any, key string, defVal ...any) any {
    data := this.Find(source, key)
    if data != nil {
        return data
    }

    if len(defVal) > 0 {
        return defVal[0]
    }

    return nil
}

// 查找
func (this Arr) Find(source map[string]any, key string) any {
    lowerKey := strings.ToLower(key)

    var (
        val    any
        path   = strings.Split(lowerKey, this.keyDelim)
        nested = len(path) > 1
    )

    // 索引
    val = this.searchIndexableWithPathPrefixes(source, path)
    if val != nil {
        return val
    }

    if nested && this.isPathShadowedInDeepMap(path, source) != "" {
        return nil
    }

    // map
    val = this.searchMap(source, path)
    if val != nil {
        return val
    }

    return nil
}

// 数组
func (this Arr) searchMap(source map[string]any, path []string) any {
    if len(path) == 0 {
        return source
    }

    next, ok := source[path[0]]
    if !ok {
        return nil
    }

    if len(path) == 1 {
        return next
    }

    switch n := next.(type) {
        case map[any]any:
            return this.searchMap(toStringMap(n), path[1:])
        case map[string]any:
            return this.searchMap(n, path[1:])
        default:
            if nextMap, isMap := this.anyMapFormat(next); isMap {
                return this.searchMap(toStringMap(nextMap), path[1:])
            }
    }

    return nil
}

// 索引查询
func (this Arr) searchIndexableWithPathPrefixes(source any, path []string) any {
    if len(path) == 0 {
        return source
    }

    for i := len(path); i > 0; i-- {
        prefixKey := strings.ToLower(strings.Join(path[0:i], this.keyDelim))

        var val any
        switch sourceIndexable := source.(type) {
            case []any:
                val = this.searchSliceWithPathPrefixes(sourceIndexable, prefixKey, i, path)
            case map[string]any:
                val = this.searchMapWithPathPrefixes(sourceIndexable, prefixKey, i, path)
        }

        if val != nil {
            return val
        }
    }

    return nil
}

// 切片
func (this Arr) searchSliceWithPathPrefixes(
    sourceSlice []any,
    prefixKey string,
    pathIndex int,
    path []string,
) any {
    index, err := strconv.Atoi(prefixKey)
    if err != nil || len(sourceSlice) <= index {
        return nil
    }

    next := sourceSlice[index]

    if pathIndex == len(path) {
        return next
    }

    switch n := next.(type) {
        case map[any]any:
            return this.searchIndexableWithPathPrefixes(toStringMap(n), path[pathIndex:])
        case map[string]any, []any:
            return this.searchIndexableWithPathPrefixes(n, path[pathIndex:])
        default:
            if nextMap, isMap := this.anyMapFormat(next); isMap {
                return this.searchIndexableWithPathPrefixes(toStringMap(nextMap), path[pathIndex:])
            }
    }

    return nil
}

// map 数据
func (this Arr) searchMapWithPathPrefixes(
    sourceMap map[string]any,
    prefixKey string,
    pathIndex int,
    path []string,
) any {
    next, ok := sourceMap[prefixKey]
    if !ok {
        return nil
    }

    if pathIndex == len(path) {
        return next
    }

    switch n := next.(type) {
        case map[any]any:
            return this.searchIndexableWithPathPrefixes(toStringMap(n), path[pathIndex:])
        case map[string]any, []any:
            return this.searchIndexableWithPathPrefixes(n, path[pathIndex:])
        default:
            if nextMap, isMap := this.anyMapFormat(next); isMap {
                return this.searchIndexableWithPathPrefixes(toStringMap(nextMap), path[pathIndex:])
            }
    }

    return nil
}

// 是否合适
func (this Arr) isPathShadowedInDeepMap(path []string, m map[string]any) string {
    var parentVal any

    for i := 1; i < len(path); i++ {
        parentVal = this.searchMap(m, path[0:i])
        if parentVal == nil {
            return ""
        }

        switch parentVal.(type) {
            case map[any]any:
                continue
            case map[string]any:
                continue
            default:
                parentValKind := reflect.TypeOf(parentVal).Kind()
                if parentValKind == reflect.Map {
                    continue
                }

                return strings.Join(path[0:i], this.keyDelim)
        }
    }

    return ""
}

// any map 数据格式化
func (this Arr) anyMapFormat(data any) (map[any]any, bool) {
    m := make(map[any]any)
    isMap := false

    dataKind := reflect.TypeOf(data).Kind()
    if dataKind == reflect.Map {
        iter := reflect.ValueOf(data).MapRange()
        for iter.Next() {
            k := iter.Key().Interface()
            v := iter.Value().Interface()

            m[k] = v
        }

        isMap = true
    }

    return m, isMap
}

// 构造函数
func NewArr() Arr {
    return Arr{
        keyDelim: ".",
    }
}

// 构造函数
func New() Arr {
    return NewArr()
}
