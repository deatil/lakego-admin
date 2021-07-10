package route

import (
    "github.com/gin-gonic/gin"
    
    "lakego-admin/lakego/http/route/middleware"
)

/**
 * 获取中间件
 */
func GetMiddlewares(name string) []gin.HandlerFunc {
    m := middleware.GetInstance()
    
    middlewares := m.GetHandlerFuncMiddlewares(name)

    return middlewares
}