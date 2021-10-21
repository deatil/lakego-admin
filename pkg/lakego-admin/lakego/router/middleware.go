package router

import (
    "sync"
)

var instance *Middleware
var once sync.Once

/**
 * 单例模式
 */
func NewWithInstance() *Middleware {
    once.Do(func() {
        instance = New()
    })

    return instance
}

/**
 * New
 */
func New() *Middleware {
    global := "lakego::router-group"

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
func (this *Middleware) WithGlobal(global string) *Middleware {
    this.global = global

    return this
}

/**
 * 全局名称
 */
func (this *Middleware) GetGlobal() string {
    return this.global
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
func (this *Middleware) MiddlewareGroup(name string, middleware interface{}) *Middleware {
    this.group.Push(name, middleware)

    return this
}

/**
 * 全局中间前置
 */
func (this *Middleware) PrependMiddleware(middleware interface{}) *Middleware {
    this.group.Prepend(this.global, middleware)

    return this
}

/**
 * 全局中间后置
 */
func (this *Middleware) PushMiddleware(middleware interface{}) *Middleware {
    this.group.Push(this.global, middleware)

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
    return this.GetMiddlewareList(this.global)
}

