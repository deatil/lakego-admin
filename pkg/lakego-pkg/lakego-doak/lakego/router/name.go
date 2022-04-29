package router

import (
    "sync"
)

var instanceName *RouteName
var onceName sync.Once

// 单例
func NewName() *RouteName {
    onceName.Do(func() {
        instanceName = &RouteName{
            routes: make(RouterInfoMap),
        }
    })

    return instanceName
}

// 单例
func Name(name string) *RouteName {
    return NewName().SetName(name)
}

// 别名信息
/*
type RouteInfo struct {
    Method      string
    Path        string
    Handler     string
    HandlerFunc HandlerFunc
}
*/
type RouterInfo struct {
    // 默认
    RouteInfo

    // 别名
    Name string
}

// 存储别名
type (
    // map 列表
    RouterInfoMap = map[string]RouterInfo
)

/**
 * 别名
 *
 * @create 2022-3-7
 * @author deatil
 */
type RouteName struct {
    // 锁定
    mu sync.RWMutex

    // 列表
    routes RouterInfoMap
}

// 设置
func (this *RouteName) SetRouteName(name string, route RouterInfo) *RouteName {
    this.mu.Lock()
    defer this.mu.Unlock()

    this.routes[name] = route

    return this
}

// 设置别名
func (this *RouteName) SetName(name string) *RouteName {
    this.mu.Lock()
    defer this.mu.Unlock()

    route := NewRoute().GetLastRoute()

    this.routes[name] = RouterInfo{
        route,
        name,
    }

    return this
}

// 获取全部
func (this *RouteName) GetRoutes() RouterInfoMap {
    return this.routes
}

// 获取单个
func (this *RouteName) GetRoute(name string) RouterInfo {
    if route, ok := this.routes[name]; ok {
        return route
    }

    return RouterInfo{}
}
