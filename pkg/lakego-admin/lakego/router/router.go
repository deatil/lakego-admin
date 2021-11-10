package router

import (
    "net/http"

    "github.com/gin-gonic/gin"
)

// 中间件
type HandlerFunc = gin.HandlerFunc

// 中间件列表
type HandlersChain = gin.HandlersChain

// 路由信息
type RouteInfo = gin.RouteInfo

// 路由信息列表
type RoutesInfo = gin.RoutesInfo

// 路由
type Engine = gin.Engine

// 路由接口
type IRouter = gin.IRouter

// 路由接口列表
type IRoutes = gin.IRoutes

// 路由分组
type RouterGroup = gin.RouterGroup

// gin 输出数据格式
type H = gin.H

// Accounts
type Accounts = gin.Accounts

// 上下文
type Context = gin.Context

// Negotiate
type Negotiate = gin.Negotiate

// 错误码类型
type ErrorType = gin.ErrorType

// 错误
type Error = gin.Error

// LoggerConfig
type LoggerConfig = gin.LoggerConfig

// LogFormatter
type LogFormatter = gin.LogFormatter

// LogFormatterParams
type LogFormatterParams = gin.LogFormatterParams

// 请求数据
type Param = gin.Param

// 请求数据列表
type Params = gin.Params

// 响应
type ResponseWriter = gin.ResponseWriter

// Bind
func Bind(val interface{}) HandlerFunc {
    return gin.Bind(val)
}

// WrapF
func WrapF(f http.HandlerFunc) HandlerFunc {
    return gin.WrapF(f)
}

// WrapF
func WrapH(h http.Handler) HandlerFunc {
    return gin.WrapH(h)
}

// 使用 gin
func NewGin() *Engine {
    return gin.New()
}

// 默认 gin
func DefaultGin() *Engine {
    return gin.Default()
}

// 是否为调试
func IsDebugging() bool {
    return gin.IsDebugging()
}

// 文件夹
func Dir(root string, listDirectory bool) http.FileSystem {
    return gin.Dir(root, listDirectory)
}

