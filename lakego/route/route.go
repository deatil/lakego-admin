package route

import (
    "sync"

    "github.com/gin-gonic/gin"
)

var instance *Route
var once sync.Once

func New() *Route {
    once.Do(func() {
        instance = &Route{}
    })

    return instance
}

/**
 * 缓存路由信息
 *
 * @create 2021-9-7
 * @author deatil
 */
type Route struct {
    // 路由
    routeEngine *gin.Engine
}

// 设置
func (r *Route) With(engine *gin.Engine) {
    r.routeEngine = engine
}

// 设置
func (r *Route) Get() *gin.Engine {
    return r.routeEngine
}

// 路由信息
/*
type RouteInfo struct {
    Method      string
    Path        string
    Handler     string
    HandlerFunc HandlerFunc
}
RoutesInfo []RouteInfo
*/
func (r *Route) GetRoutes() gin.RoutesInfo {
    return r.routeEngine.Routes()
}

// 路由信息
func (r *Route) GetRouteMap() map[string]interface{} {
    routes := r.GetRoutes()

    newRoutes := make(map[string]interface{})
    for _, v := range routes {
        if newRoute, ok := newRoutes[v.Method]; ok {
            newRoute = append(newRoute.([]string), v.Path)
            newRoutes[v.Method] = newRoute
        } else {
            newRoutes[v.Method] = []string{v.Path}
        }
    }

    return newRoutes
}

