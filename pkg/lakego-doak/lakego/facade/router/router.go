package router

import (
    "github.com/deatil/lakego-doak/lakego/router"
)

/**
 * 获取中间件单列
 */
func NewMiddleware() *router.Middleware {
    return router.NewMiddlewareWithInstance()
}

/**
 * 获取中间件列表
 */
func GetMiddlewares(name string) (handlerFuncs []router.HandlerFunc) {
    m := NewMiddleware()

    middlewares := m.GetMiddlewareList(name)

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            switch middlewareItem.(type) {
                case router.HandlerFunc:
                    handlerFuncs = append(handlerFuncs, middlewareItem.(router.HandlerFunc))
            }
        }
    }

    return
}

/**
 * 获取全局中间件列表
 */
func GetGlobalMiddlewares() (handlerFuncs []router.HandlerFunc) {
    m := NewMiddleware()

    middlewares := m.GetGlobalMiddlewareList()

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            switch middlewareItem.(type) {
                case router.HandlerFunc:
                    handlerFuncs = append(handlerFuncs, middlewareItem.(router.HandlerFunc))
            }
        }
    }

    return
}

