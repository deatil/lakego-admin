package router

/**
 * 中间件别名
 */
func AliasMiddleware(name string, middleware any) {
    DefaultMiddleware().AliasMiddleware(name, middleware)
}

/**
 * 中间件分组
 */
func MiddlewareGroup(name string, middlewares []any) {
    DefaultMiddleware().MiddlewareGroup(name, middlewares)
}

/**
 * 添加全局中间件
 */
func PushMiddleware(middleware any) {
    DefaultMiddleware().PushMiddleware(middleware)
}

/**
 * 获取中间件列表
 */
func GetMiddlewares(name string) (handlerFuncs []HandlerFunc) {
    m := DefaultMiddleware()

    middlewares := m.GetMiddlewareList(name)

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            switch middlewareItem.(type) {
                case HandlerFunc:
                    handlerFuncs = append(handlerFuncs, middlewareItem.(HandlerFunc))
            }
        }
    }

    return
}

/**
 * 获取全局中间件列表
 */
func GetGlobalMiddlewares() (handlerFuncs []HandlerFunc) {
    m := DefaultMiddleware()

    middlewares := m.GetGlobalMiddlewareList()

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            switch middlewareItem.(type) {
                case HandlerFunc:
                    handlerFuncs = append(handlerFuncs, middlewareItem.(HandlerFunc))
            }
        }
    }

    return
}

