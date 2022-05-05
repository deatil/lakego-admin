package interfaces

/**
 * 驱动接口
 *
 * @create 2021-7-15
 * @author deatil
 */
type Driver interface {
    // 判断是否存在
    Exists(string) bool

    // 获取
    Get(string) (any, error)

    // 存储
    Put(string, any, int64) error

    // 存储一个不过期的数据
    Forever(string, any) error

    // 自增
    Increment(string, ...int64) error

    // 自减
    Decrement(string, ...int64) error

    // 删除
    Forget(string) (bool, error)

    // 清空所有缓存
    Flush() (bool, error)

    // 设置前缀
    SetPrefix(string)

    // 缓存字段前缀
    GetPrefix() string
}

