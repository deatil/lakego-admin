package router

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/gin-gonic/gin/render"
    "github.com/gin-gonic/gin/binding"
)

const (
    // 调试模式
    DebugMode = gin.DebugMode
    // 线上模式
    ReleaseMode = gin.ReleaseMode
    // 测试模式
    TestMode = gin.TestMode
)

type (
    // 中间件
    HandlerFunc = gin.HandlerFunc

    // 中间件列表
    HandlersChain = gin.HandlersChain

    // 路由信息
    RouteInfo = gin.RouteInfo

    // 路由信息列表
    RoutesInfo = gin.RoutesInfo

    // 路由
    Engine = gin.Engine

    // 路由接口
    IRouter = gin.IRouter

    // 路由接口列表
    IRoutes = gin.IRoutes

    // 路由分组
    RouterGroup = gin.RouterGroup

    // gin 输出数据格式
    H = gin.H

    // Accounts
    Accounts = gin.Accounts

    // 上下文
    Context = gin.Context

    // Negotiate
    Negotiate = gin.Negotiate

    // 错误码类型
    ErrorType = gin.ErrorType

    // 错误
    Error = gin.Error

    // LoggerConfig
    LoggerConfig = gin.LoggerConfig

    // LogFormatter
    LogFormatter = gin.LogFormatter

    // LogFormatterParams
    LogFormatterParams = gin.LogFormatterParams

    // 请求数据
    Param = gin.Param

    // 请求数据列表
    Params = gin.Params

    // 响应
    ResponseWriter = gin.ResponseWriter

    // Render
    Render = render.Render

    // Binding
    Binding = binding.Binding

    // BindingBody
    BindingBody = binding.BindingBody
)

// 使用 gin
func New() *Engine {
    return gin.New()
}

// 默认 gin
func Default() *Engine {
    return gin.Default()
}

// 设置模式
func SetMode(value string) {
    gin.SetMode(value)
}

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

// 是否为调试
func IsDebugging() bool {
    return gin.IsDebugging()
}

// 文件夹
func Dir(root string, listDirectory bool) http.FileSystem {
    return gin.Dir(root, listDirectory)
}

// gin 默认回收中间件
func Recovery() HandlerFunc {
    return gin.Recovery()
}

// gin 默认日志中间件
func Logger() HandlerFunc {
    return gin.Logger()
}

