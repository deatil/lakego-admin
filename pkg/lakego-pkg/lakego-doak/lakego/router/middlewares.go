package router

/**
 * New
 */
func NewMiddlewares() *Middlewares {
    middlewares:= make([]any, 0)

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
    middlewares []any
}

/**
 * 覆写
 */
func (this *Middlewares) With(middlewares []any) *Middlewares {
    this.middlewares = middlewares

    return this
}

/**
 * 前置添加
 */
func (this *Middlewares) Prepend(middlewares ...any) *Middlewares {
    this.middlewares = append(middlewares, this.middlewares...)

    return this
}

/**
 * 后置添加
 */
func (this *Middlewares) Push(middlewares ...any) *Middlewares {
    this.middlewares = append(this.middlewares, middlewares...)

    return this
}

/**
 * 移除
 */
func (this *Middlewares) Remove(middleware any) bool {
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
func (this *Middlewares) All() []any {
    return this.middlewares
}
