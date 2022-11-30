package array

import (
    "reflect"
    "strconv"
    "strings"
)

// 构造函数
func New() Arr {
    return NewArr()
}

// 构造函数
func NewArr() Arr {
    return Arr{
        keyDelim: ".",
    }
}

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
func (this Arr) Exists(source any, key string) bool {
    if this.Find(source, key) != nil {
        return true
    }

    return false
}

// 获取
func (this Arr) Get(source any, key string, defVal ...any) any {
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
func (this Arr) Find(source any, key string) any {
    var (
        val    any
        path   = strings.Split(key, this.keyDelim)
        nested = len(path) > 1
    )

    newSource, isMap := this.anyDataMapFormat(source)
    if isMap {
        // map
        val = this.searchMap(newSource, path)
        if val != nil {
            return val
        }
    }

    // 格式化
    source = this.anyDataFormat(source)

    // 索引
    val = this.searchIndexWithPathPrefixes(source, path)
    if val != nil {
        return val
    }

    if nested && this.isPathShadowedInDeepMap(path, newSource) != "" {
        return nil
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
func (this Arr) searchIndexWithPathPrefixes(source any, path []string) any {
    if len(path) == 0 {
        return source
    }

    for i := len(path); i > 0; i-- {
        prefixKey := strings.Join(path[0:i], this.keyDelim)

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

    n := this.anyDataFormat(next)
    if n != nil {
        return this.searchIndexWithPathPrefixes(n, path[pathIndex:])
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

    n := this.anyDataFormat(next)
    if n != nil {
        return this.searchIndexWithPathPrefixes(n, path[pathIndex:])
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

// any data 数据格式化
func (this Arr) anyDataFormat(data any) any {
    switch n := data.(type) {
        case map[any]any:
            return toStringMap(n)
        case map[string]any, []any:
            return n
        default:
            dataMap, isMap := this.anyMapFormat(data)
            if isMap {
                return toStringMap(dataMap)
            }

            if dataSlice, isSlice := this.anySliceFormat(data); isSlice {
                return dataSlice
            }
    }

    return nil
}

// any data map 数据格式化
func (this Arr) anyDataMapFormat(data any) (map[string]any, bool) {
    switch n := data.(type) {
        case map[any]any:
            return toStringMap(n), true
        case map[string]any:
            return n, true
        default:
            dataMap, isMap := this.anyMapFormat(data)
            if isMap {
                return toStringMap(dataMap), true
            }
    }

    return nil, false
}

// any map 数据格式化
func (this Arr) anyMapFormat(data any) (map[any]any, bool) {
    m := make(map[any]any)
    isMap := false

    dataValue := reflect.ValueOf(data)
    for dataValue.Kind() == reflect.Pointer {
        dataValue = dataValue.Elem()
    }

    // 获取最后的数据
    newData := dataValue.Interface()

    newDataKind := reflect.TypeOf(newData).Kind()
    if newDataKind == reflect.Map {
        iter := reflect.ValueOf(newData).MapRange()
        for iter.Next() {
            k := iter.Key().Interface()
            v := iter.Value().Interface()

            m[k] = v
        }

        isMap = true
    }

    return m, isMap
}

// any Slice 数据格式化
func (this Arr) anySliceFormat(data any) ([]any, bool) {
    m := make([]any, 0)
    isSlice := false

    dataValue := reflect.ValueOf(data)
    for dataValue.Kind() == reflect.Pointer {
        dataValue = dataValue.Elem()
    }

    // 获取最后的数据
    newData := dataValue.Interface()

    newDataKind := reflect.TypeOf(newData).Kind()
    if newDataKind == reflect.Slice {
        newDataValue := reflect.ValueOf(newData)
        newDataLen := newDataValue.Len()

        for i := 0; i < newDataLen; i++ {
            v := newDataValue.Index(i).Interface()

            m = append(m, v)
        }

        isSlice = true
    }

    return m, isSlice
}
