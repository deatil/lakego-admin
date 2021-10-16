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
 * 前置添加
 */
func (m *Middlewares) Prepend(middlewares ...interface{}) *Middlewares {
    m.middlewares = append(middlewares, m.middlewares...)

    return m
}

/**
 * 后置添加
 */
func (m *Middlewares) Push(middlewares ...interface{}) *Middlewares {
    m.middlewares = append(m.middlewares, middlewares...)

    return m
}

/**
 * 覆写
 */
func (m *Middlewares) With(middlewares []interface{}) *Middlewares {
    m.middlewares = middlewares

    return m
}

/**
 * 移除
 */
func (m *Middlewares) Remove(middleware interface{}) bool {
    for i, item := range m.middlewares {
        if middleware == item {
            m.middlewares = append(m.middlewares[:i], m.middlewares[i + 1:]...)

            return true
        }
    }

    return false
}

/**
 * 全部
 */
func (m *Middlewares) All() []interface{} {
    return m.middlewares
}
