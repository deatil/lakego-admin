package array

// 判断是否存在
func Exists(source map[string]any, key string) bool {
    return New().Exists(source, key)
}

// 获取
func Get(source map[string]any, key string, defVal ...any) any {
    return New().Get(source, key, defVal...)
}

// 查找
func Find(source map[string]any, key string) any {
    return New().Find(source, key)
}

var ArrGet    = Get
var ArrFind   = Find
var ArrExists = Exists
