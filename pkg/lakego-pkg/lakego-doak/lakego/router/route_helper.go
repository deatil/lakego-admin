package router

/**
 * 中间件别名
 */
func AliasMiddleware(name string, middleware any) {
    InstanceMiddleware().AliasMiddleware(name, middleware)
}

/**
 * 中间件分组
 */
func MiddlewareGroup(name string, middlewares []any) {
    InstanceMiddleware().MiddlewareGroup(name, middlewares)
}

/**
 * 获取中间件列表
 */
func GetMiddlewares(name string) (handlerFuncs []HandlerFunc) {
    m := InstanceMiddleware()

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
    m := InstanceMiddleware()

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

