package router

/**
 * New
 */
func NewMiddlewares() *Middlewares {
    middlewares:= make([]interface{}, 0)

    return &Middlewares{
        middlewares: middlewares,
    }
}

/**
 * 中间件切片
 *
 * @create 2021-10-16
 * @author deatil
 */
type Middlewares struct {
    // 中间件
    middlewares []interface{}
}

/**
 * 覆写
 */
func (this *Middlewares) With(middlewares []interface{}) *Middlewares {
    this.middlewares = middlewares

    return this
}

/**
 * 前置添加
 */
func (this *Middlewares) Prepend(middlewares ...interface{}) *Middlewares {
    this.middlewares = append(middlewares, this.middlewares...)

    return this
}

/**
 * 后置添加
 */
func (this *Middlewares) Push(middlewares ...interface{}) *Middlewares {
    this.middlewares = append(this.middlewares, middlewares...)

    return this
}

/**
 * 移除
 */
func (this *Middlewares) Remove(middleware interface{}) bool {
    for i, item := range this.middlewares {
        if middleware == item {
            this.middlewares = append(this.middlewares[:i], this.middlewares[i + 1:]...)

            return true
        }
    }

    return false
}

/**
 * 全部
 */
func (this *Middlewares) All() []interface{} {
    return this.middlewares
}
