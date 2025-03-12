package router

// 使用设置的中间件
func Use(engine IRoutes, middlewareName string) IRoutes {
    middlewares := GetMiddlewares(middlewareName)
    engine.Use(middlewares...)

    return engine
}

// 使用设置的中间件设置分组
func Group(engine IRouter, relativePath string, middlewareName string) IRouter {
    middlewares := GetMiddlewares(middlewareName)
    routerGroup := engine.Group(relativePath, middlewares...)

    return routerGroup
}

// 中间件别名
func AliasMiddleware(name string, middleware any) {
    DefaultMiddleware().AliasMiddleware(name, middleware)
}

// 中间件分组
func MiddlewareGroup(name string, middlewares []any) {
    DefaultMiddleware().MiddlewareGroup(name, middlewares)
}

// 中间件分组 - 前置
func PrependMiddlewareToGroup(name string, middleware any) {
    DefaultMiddleware().PrependMiddlewareToGroup(name, middleware)
}

// 中间件分组 - 后置
func PushMiddlewareToGroup(name string, middleware any) {
    DefaultMiddleware().PushMiddlewareToGroup(name, middleware)
}

// 添加全局前置中间件
func PrependMiddleware(middleware any) {
    DefaultMiddleware().PrependMiddleware(middleware)
}

// 添加全局后置中间件
func PushMiddleware(middleware any) {
    DefaultMiddleware().PushMiddleware(middleware)
}

// 获取中间件列表
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

// 获取全局中间件列表
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

