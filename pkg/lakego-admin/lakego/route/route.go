package route

import (
    "sync"

    "github.com/deatil/lakego-admin/lakego/router"
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
    routeEngine *router.Engine
}

// 设置
func (this *Route) With(engine *router.Engine) {
    this.routeEngine = engine
}

// 设置
func (this *Route) Get() *router.Engine {
    return this.routeEngine
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
func (this *Route) GetRoutes() router.RoutesInfo {
    return this.routeEngine.Routes()
}

// 路由信息
func (this *Route) GetRouteMap() map[string]interface{} {
    routes := this.GetRoutes()

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

