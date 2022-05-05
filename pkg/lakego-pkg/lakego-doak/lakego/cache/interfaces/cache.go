package interfaces

/**
 * 缓存接口
 *
 * @create 2021-7-15
 * @author deatil
 */
type Cache interface {
    // 设置驱动
    WithDriver(Driver) Cache

    // 获取驱动
    GetDriver() Driver

    // 设置配置
    WithConfig(map[string]any) Cache

    // 获取配置
    GetConfig(string) any

    // 判断
    Has(string) bool

    // 获取
    Get(string) (any, error)

    // 存储
    Put(string, any, int64) error

    // 存储一个不过期的数据
    Forever(string, any) error

    // 获取后删除
    Pull(string) (any, error)

    // 自增
    Increment(string, ...int64) error

    // 自减
    Decrement(string, ...int64) error

    // 删除
    Forget(string) (bool, error)

    // 清空所有缓存
    Flush() (bool, error)

    // 缓存字段前缀
    GetPrefix() string
}

