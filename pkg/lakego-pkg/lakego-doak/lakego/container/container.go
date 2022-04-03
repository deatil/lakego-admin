package container

import (
    "sync"
    "strings"
)

var instance *Container
var once sync.Once

// 单例
func Instance() *Container {
    once.Do(func() {
        instance = New()
    })

    return instance
}

// 构造函数
func New() *Container {
    return &Container{}
}

/**
 * 容器结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type Container struct {
    // sync 数据
    SyncMap sync.Map
}

// 键值对的形式将代码注册到容器
func (this *Container) Set(key string, value interface{}) bool {
    // 存在则删除旧的
    if exists := this.Exists(key); exists {
        this.Delete(key)
    }

    this.SyncMap.Store(key, value)

    return true
}

/**
 * 单值批量设置
 */
func (this *Container) SetItems(key string, value interface{}) bool {
    var newValues []interface{}

    if newValue, exists := this.SyncMap.Load(key); exists {
        // 强制转换为 []interface{} 后增加数据
        newValues = append(newValue.([]interface{}), value)
    } else {
        newValues = append(newValues, value)
    }

    this.SyncMap.Store(key, newValues)

    return true
}

// 取值
func (this *Container) Get(key string) interface{} {
    if value, exists := this.SyncMap.Load(key); exists {
        return value
    }

    return nil
}

// 判断是否存在
func (this *Container) Exists(key string) bool {
    if _, exists := this.SyncMap.Load(key); exists {
        return true
    }

    return false
}

// 删除
func (this *Container) Delete(key string) bool {
    this.SyncMap.Delete(key)

    return true
}

// 按照键的前缀删除容器中注册的内容
func (this *Container) FuzzyDelete(keyPre string) {
    this.SyncMap.Range(func(key, value interface{}) bool {
        if keyname, ok := key.(string); ok {
            if strings.HasPrefix(keyname, keyPre) {
                this.SyncMap.Delete(keyname)
            }
        }

        return true
    })
}
