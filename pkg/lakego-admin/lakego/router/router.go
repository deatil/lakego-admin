package router

import (
    "io"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/gin-gonic/gin/render"
    "github.com/gin-gonic/gin/binding"
)

const (
    // 模式
    EnvGinMode = gin.EnvGinMode

    // 调试模式
    DebugMode = gin.DebugMode

    // 线上模式
    ReleaseMode = gin.ReleaseMode

    // 测试模式
    TestMode = gin.TestMode
)

// 默认写入
var DefaultWriter = gin.DefaultWriter

// 默认错误写入
var DefaultErrorWriter = gin.DefaultErrorWriter

type (
    // 中间件
    HandlerFunc = gin.HandlerFunc

    // 中间件列表
    HandlersChain = gin.HandlersChain

    // gin 输出数据
    H = gin.H

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

    // 上下文
    Context = gin.Context

    // Negotiate
    Negotiate = gin.Negotiate

    // 错误码类型
    ErrorType = gin.ErrorType

    // 错误
    Error = gin.Error

    // 请求数据
    Param = gin.Param

    // 请求数据列表
    Params = gin.Params

    // 响应
    ResponseWriter = gin.ResponseWriter

    // 验证
    Accounts = gin.Accounts

    // RecoveryFunc
    RecoveryFunc = gin.RecoveryFunc

    // LoggerConfig
    LoggerConfig = gin.LoggerConfig

    // LogFormatter
    LogFormatter = gin.LogFormatter

    // LogFormatterParams
    LogFormatterParams = gin.LogFormatterParams
)

type (
    // Render
    Render = render.Render
)

type (
    // Binding
    Binding = binding.Binding

    // BindingBody
    BindingBody = binding.BindingBody

    // BindingUri
    BindingUri = binding.BindingUri

    // StructValidator
    StructValidator = binding.StructValidator
)

var Validator = binding.Validator

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

// DisableBindValidation closes the default validator.
func DisableBindValidation() {
    gin.DisableBindValidation()
}

// EnableJsonDecoderUseNumber sets true for binding.EnableDecoderUseNumber to
// call the UseNumber method on the JSON Decoder instance.
func EnableJsonDecoderUseNumber() {
    gin.EnableJsonDecoderUseNumber()
}

// EnableJsonDecoderDisallowUnknownFields sets true for binding.EnableDecoderDisallowUnknownFields to
// call the DisallowUnknownFields method on the JSON Decoder instance.
func EnableJsonDecoderDisallowUnknownFields() {
    gin.EnableJsonDecoderDisallowUnknownFields()
}

// Mode returns currently gin mode.
func Mode() string {
    return gin.Mode()
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

// 文件夹
func Dir(root string, listDirectory bool) http.FileSystem {
    return gin.Dir(root, listDirectory)
}

// 是否为调试
func IsDebugging() bool {
    return gin.IsDebugging()
}

// BindingDefault
func BindingDefault(method, contentType string) Binding {
    return binding.Default(method, contentType)
}

// gin 默认回收中间件
func Recovery() HandlerFunc {
    return gin.Recovery()
}

// CustomRecovery returns a middleware that recovers from any panics and calls the provided handle func to handle it.
func CustomRecovery(handle RecoveryFunc) HandlerFunc {
    return gin.CustomRecovery(handle)
}

// RecoveryWithWriter returns a middleware for a given writer that recovers from any panics and writes a 500 if there was one.
func RecoveryWithWriter(out io.Writer, recovery ...RecoveryFunc) HandlerFunc {
    return gin.RecoveryWithWriter(out, recovery...)
}

// CustomRecoveryWithWriter returns a middleware for a given writer that recovers from any panics and calls the provided handle func to handle it.
func CustomRecoveryWithWriter(out io.Writer, handle RecoveryFunc) HandlerFunc {
    return gin.CustomRecoveryWithWriter(out, handle)
}

// gin 默认日志中间件
func Logger() HandlerFunc {
    return gin.Logger()
}

// DisableConsoleColor disables color output in the console.
func DisableConsoleColor() {
    gin.DisableConsoleColor()
}

// ForceConsoleColor force color output in the console.
func ForceConsoleColor() {
    gin.ForceConsoleColor()
}

// ErrorLogger returns a handlerfunc for any error type.
func ErrorLogger() HandlerFunc {
    return gin.ErrorLogger()
}

// ErrorLoggerT returns a handlerfunc for a given error type.
func ErrorLoggerT(typ ErrorType) HandlerFunc {
    return gin.ErrorLoggerT(typ)
}

// LoggerWithFormatter instance a Logger middleware with the specified log format function.
func LoggerWithFormatter(f LogFormatter) HandlerFunc {
    return gin.LoggerWithFormatter(f)
}

// LoggerWithWriter instance a Logger middleware with the specified writer buffer.
// Example: os.Stdout, a file opened in write mode, a socket...
func LoggerWithWriter(out io.Writer, notlogged ...string) HandlerFunc {
    return gin.LoggerWithWriter(out, notlogged...)
}

// LoggerWithConfig instance a Logger middleware with config.
func LoggerWithConfig(conf LoggerConfig) HandlerFunc {
    return gin.LoggerWithConfig(conf)
}

// BasicAuthForRealm
func BasicAuthForRealm(accounts Accounts, realm string) HandlerFunc {
    return gin.BasicAuthForRealm(accounts, realm)
}

// BasicAuth
func BasicAuth(accounts Accounts) HandlerFunc {
    return gin.BasicAuth(accounts)
}

