package interfaces

import (
    "time"
)

// 驱动接口
type Driver interface {
    // 初始化配置
    Init(map[string]interface{}) Driver

    // 获取
    Get(string) (interface{}, error)

    // 存储
    Put(string, interface{}, time.Duration) error

    // 存储一个不过期的数据
    Forever(string, interface{}) error

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

