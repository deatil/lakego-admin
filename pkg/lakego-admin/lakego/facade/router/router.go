package router

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/router"
)

/**
 * 获取中间件单列
 */
func New() *router.Middleware {
    return router.NewWithInstance()
}

/**
 * 获取中间件列表
 */
func GetMiddlewares(name string) (handlerFuncs []gin.HandlerFunc) {
    m := New()

    middlewares := m.GetMiddlewareList(name)

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            switch middlewareItem.(type) {
                case gin.HandlerFunc:
                    handlerFuncs = append(handlerFuncs, middlewareItem.(gin.HandlerFunc))
            }
        }
    }

    return
}

/**
 * 获取全局中间件列表
 */
func GetGlobalMiddlewares() (handlerFuncs []gin.HandlerFunc) {
    m := New()

    middlewares := m.GetGlobalMiddlewareList()

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            switch middlewareItem.(type) {
                case gin.HandlerFunc:
                    handlerFuncs = append(handlerFuncs, middlewareItem.(gin.HandlerFunc))
            }
        }
    }

    return
}

