package router

import (
    "sync"
)

var instance *Middleware
var once sync.Once

/**
 * 单例模式
 */
func GetInstance() *Middleware {
    once.Do(func() {
        instance = New()
    })

    return instance
}

/**
 * New
 */
func New() *Middleware {
    global := "lakego::group"

    alias := NewAlias()
    middlewares := NewMiddlewares()
    group := NewGroup()

    return &Middleware{
        global: global,
        alias: alias,
        middlewares: middlewares,
        group: group,
    }
}

/**
 * 中间件
 *
 * @create 2021-9-15
 * @author deatil
 */
type Middleware struct {
    // 全局名称
    global string

    // 别名
    alias *Alias

    // 中间件
    middlewares *Middlewares

    // 中间件分组
    group *Group
}

/**
 * 全局名称
 */
func (m *Middleware) WithGlobal(global string) *Middleware {
    m.global = global

    return m
}

/**
 * 全局名称
 */
func (m *Middleware) GetGlobal() string {
    return m.global
}

/**
 * 别名
 */
func (m *Middleware) WithAlias(alias *Alias) *Middleware {
    m.alias = alias

    return m
}

/**
 * 别名
 */
func (m *Middleware) GetAlias() *Alias {
    return m.alias
}

/**
 * 中间件
 */
func (m *Middleware) WithMiddlewares(middlewares *Middlewares) *Middleware {
    m.middlewares = middlewares

    return m
}

/**
 * 中间件
 */
func (m *Middleware) GetMiddlewares() *Middlewares {
    return m.middlewares
}

/**
 * 中间件分组
 */
func (m *Middleware) WithGroup(group *Group) *Middleware {
    m.group = group

    return m
}

/**
 * 中间件分组
 */
func (m *Middleware) GetGroup() *Group {
    return m.group
}

/**
 * 别名
 */
func (m *Middleware) AliasMiddleware(name string, middleware interface{}) *Middleware {
    m.alias.With(name, middleware)

    return m
}

/**
 * 中间件分组
 */
func (m *Middleware) MiddlewareGroup(name string, middleware interface{}) *Middleware {
    m.group.Push(name, middleware)

    return m
}

/**
 * 全局中间前置
 */
func (m *Middleware) PrependMiddleware(middleware interface{}) *Middleware {
    m.group.Prepend(m.global, middleware)

    return m
}

/**
 * 全局中间后置
 */
func (m *Middleware) PushMiddleware(middleware interface{}) *Middleware {
    m.group.Push(m.global, middleware)

    return m
}

/**
 * 获取中间件列表
 */
func (m *Middleware) GetMiddlewareList(name string) (middleware []interface{}) {
    if nameMiddleware := m.alias.Get(name); nameMiddleware != nil {
        middleware = append(middleware, nameMiddleware)
        return
    }

    if ok := m.group.Exists(name); ok {
        nameGroupList := m.group.Get(name).All()

        for _, nameGroup := range nameGroupList {
            switch nameGroup.(type) {
                case string:
                    // 递归查询
                    data := m.GetMiddlewareList(nameGroup.(string))
                    if data != nil{
                        middleware = append(middleware, data...)
                    }
                default:
                    middleware = append(middleware, nameGroup.([]interface{}))
            }
        }
    }

    return
}

/**
 * 获取全局中间件列表
 */
func (m *Middleware) GetGlobalMiddlewareList() (middleware []interface{}) {
    return m.GetMiddlewareList(m.global)
}

