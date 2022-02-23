package router

import (
    "sync"
)

var instance *Middleware
var once sync.Once

/**
 * New
 */
func NewMiddleware() *Middleware {
    globalName := "lakego::router-group"

    alias := NewAlias()
    middlewares := NewMiddlewares()
    group := NewGroup()

    return &Middleware{
        globalName: globalName,
        alias: alias,
        middlewares: middlewares,
        group: group,
    }
}

/**
 * 单例模式
 */
func NewMiddlewareWithInstance() *Middleware {
    once.Do(func() {
        instance = NewMiddleware()
    })

    return instance
}

/**
 * 中间件
 *
 * @create 2021-9-15
 * @author deatil
 */
type Middleware struct {
    // 全局名称
    globalName string

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
func (this *Middleware) WithGlobalName(globalName string) *Middleware {
    this.globalName = globalName

    return this
}

/**
 * 全局名称
 */
func (this *Middleware) GetGlobalName() string {
    return this.globalName
}

/**
 * 别名
 */
func (this *Middleware) WithAlias(alias *Alias) *Middleware {
    this.alias = alias

    return this
}

/**
 * 别名
 */
func (this *Middleware) GetAlias() *Alias {
    return this.alias
}

/**
 * 中间件
 */
func (this *Middleware) WithMiddlewares(middlewares *Middlewares) *Middleware {
    this.middlewares = middlewares

    return this
}

/**
 * 中间件
 */
func (this *Middleware) GetMiddlewares() *Middlewares {
    return this.middlewares
}

/**
 * 中间件分组
 */
func (this *Middleware) WithGroup(group *Group) *Middleware {
    this.group = group

    return this
}

/**
 * 中间件分组
 */
func (this *Middleware) GetGroup() *Group {
    return this.group
}

/**
 * 别名
 */
func (this *Middleware) AliasMiddleware(name string, middleware interface{}) *Middleware {
    this.alias.With(name, middleware)

    return this
}

/**
 * 中间件分组
 */
func (this *Middleware) MiddlewareGroup(name string, middlewares []interface{}) *Middleware {
    this.group.With(name, middlewares)

    return this
}

/**
 * 中间件分组 - 前置
 */
func (this *Middleware) PrependMiddlewareToGroup(name string, middleware interface{}) *Middleware {
    this.group.Prepend(name, middleware)

    return this
}

/**
 * 中间件分组 - 后置
 */
func (this *Middleware) PushMiddlewareToGroup(name string, middleware interface{}) *Middleware {
    this.group.Push(name, middleware)

    return this
}

/**
 * 全局中间前置
 */
func (this *Middleware) PrependMiddleware(middleware interface{}) *Middleware {
    this.group.Prepend(this.globalName, middleware)

    return this
}

/**
 * 全局中间后置
 */
func (this *Middleware) PushMiddleware(middleware interface{}) *Middleware {
    this.group.Push(this.globalName, middleware)

    return this
}

/**
 * 获取中间件列表
 */
func (this *Middleware) GetMiddlewareList(name string) (middleware []interface{}) {
    if nameMiddleware := this.alias.Get(name); nameMiddleware != nil {
        middleware = append(middleware, nameMiddleware)
        return
    }

    if ok := this.group.Exists(name); ok {
        nameGroupList := this.group.Get(name).All()

        for _, nameGroup := range nameGroupList {
            switch nameGroup.(type) {
                case string:
                    // 递归查询
                    data := this.GetMiddlewareList(nameGroup.(string))
                    if data != nil{
                        middleware = append(middleware, data...)
                    }
                default:
                    middleware = append(middleware, nameGroup)
            }
        }
    }

    return
}

/**
 * 获取全局中间件列表
 */
func (this *Middleware) GetGlobalMiddlewareList() (middleware []interface{}) {
    return this.GetMiddlewareList(this.globalName)
}

