package route

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/http/route/middleware"
)

/**
 * 获取中间件单列
 */
func GetMiddlewareInstance() *middleware.Middleware {
    return middleware.GetInstance()
}

/**
 * 获取中间件
 */
func GetMiddleware(name string) (handlerFunc gin.HandlerFunc) {
    middleware := GetMiddlewareInstance().GetMiddleware(name)

    if middleware != nil {
        handlerFunc = middleware.(gin.HandlerFunc)
        return
    }

    handlerFunc = nil
    return
}

/**
 * 获取中间件列表
 */
func GetMiddlewares(name string) (handlerFuncs []gin.HandlerFunc) {
    m := GetMiddlewareInstance()

    middlewares := m.GetMiddlewares(name)

    if middlewares != nil && len(middlewares) > 0 {
        for _, middlewareItem := range middlewares {
            handlerFuncs = append(handlerFuncs, middlewareItem.(gin.HandlerFunc))
        }
    }

    return
}

