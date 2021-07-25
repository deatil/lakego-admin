package interfaces

// 驱动接口
type Driver interface {
    // 获取
    Get(key string) (interface{}, error)

    // 存储
    Put(key string, value interface{}, expiration interface{}) error

    // 存储一个不过期的数据
    Forever(key string, value interface{}) error

    // 自增
    Increment(key string, value ...int64) error

    // 自减
    Decrement(key string, value ...int64) error

    // 删除
    Forget(key string) (bool, error)

    // 清空所有缓存
    Flush() (bool, error)

    // 设置前缀
    SetPrefix(prefix string) error

    // 缓存字段前缀
    GetPrefix() string
}

