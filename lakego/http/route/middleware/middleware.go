package middleware

import (
    "sync"
    "github.com/gin-gonic/gin"
)

var instance *Middleware
var once sync.Once

type Middleware struct {
    // 中间件
    middlewares sync.Map

    // 中间件分组
    groups sync.Map
}

/**
 * 单例模式
 */
func GetInstance() *Middleware {
    once.Do(func() {
        instance = &Middleware{}
    })

    return instance
}

/**
 * New
 */
func New() *Middleware {
    return &Middleware{}
}

/**
 * 设置中间件
 */
func (m *Middleware) WithMiddleware(name string, middleware interface{}) bool {
    if _, exists := m.ExistMiddleware(name); exists {
        m.DeleteMiddleware(name)
    }

    m.middlewares.Store(name, middleware)

    return true
}

/**
 * 判断
 */
func (m *Middleware) ExistMiddleware(name string) (interface{}, bool) {
    return m.middlewares.Load(name)
}

/**
 * 删除
 */
func (m *Middleware) DeleteMiddleware(name string) {
    m.middlewares.Delete(name)
}

/**
 * 获取中间件
 */
func (m *Middleware) GetMiddleware(name string) interface{} {
    if value, exists := m.ExistMiddleware(name); exists {
        return value
    }
    return nil
}

/**
 * 获取中间件
 */
func (m *Middleware) GetHandlerFuncMiddleware(name string) (handlerFunc gin.HandlerFunc) {
    middleware := m.GetMiddleware(name)

    if middleware != nil {
        handlerFunc = middleware.(gin.HandlerFunc)
        return
    }

    handlerFunc = nil
    return
}

/**
 * 设置分组
 */
func (m *Middleware) WithGroup(name string, group interface{}) bool {
    var newGroups []interface{}

    if newGroup, exists := m.ExistGroup(name); exists {
        // 强制转换为 []interface{} 后增加数据
        newGroups = append(newGroup.([]interface{}), group)
    } else {
        newGroups = append(newGroups, group)
    }

    m.groups.Store(name, newGroups)

    return true
}

/**
 * 判断
 */
func (m *Middleware) ExistGroup(name string) (interface{}, bool) {
    return m.groups.Load(name)
}

/**
 * 删除
 */
func (m *Middleware) DeleteGroup(name string) {
    m.groups.Delete(name)
}

/**
 * 获取分组
 */
func (m *Middleware) GetGroup(name string) interface{} {
    if value, exists := m.ExistGroup(name); exists {
        return value
    }
    return nil
}

/**
 * 获取中间件列表
 */
func (m *Middleware) GetMiddlewares(name string) (middleware []interface{}) {
    var newData []interface{}

    if nameMiddleware, ok := m.ExistMiddleware(name); ok {
        newData = append(newData, nameMiddleware)
        return
    }

    if nameGroups, ok := m.ExistGroup(name); ok {
        nameGroupList := nameGroups.([]interface{})

        for _, s := range nameGroupList {
            switch s.(type) {
                case string:
                    // 只判断一层获取字符对应的中间件
                    data := m.GetMiddleware(s.(string))
                    if data != nil{
                        newData = append(newData, data)
                    }
                default:
                    newData = append(newData, s.([]interface{}))
            }
        }

    }

    middleware = newData
    return
}

/**
 * 获取中间件列表
 */
func (m *Middleware) GetHandlerFuncMiddlewares(name string) (handlerFuncs []gin.HandlerFunc) {
    middlewares := m.GetMiddlewares(name)

    var newMiddlewares []gin.HandlerFunc

    if middlewares != nil && len(middlewares) > 0 {
        for _, middleware := range middlewares {
            newMiddlewares = append(newMiddlewares, middleware.(gin.HandlerFunc))
        }
    }

    handlerFuncs = newMiddlewares
    return
}
