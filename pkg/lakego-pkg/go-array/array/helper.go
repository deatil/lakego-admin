package array

var defaultArr Arr

var (
    ArrGet    = Get
    ArrFind   = Find
    ArrExists = Exists
)

// 初始化
func init() {
    defaultArr = New()
}

// 获取
func Get(source any, key string, defVal ...any) any {
    return defaultArr.Get(source, key, defVal...)
}

// 查找
func Find(source any, key string) any {
    return defaultArr.Find(source, key)
}

// 判断是否存在
func Exists(source any, key string) bool {
    return defaultArr.Exists(source, key)
}
