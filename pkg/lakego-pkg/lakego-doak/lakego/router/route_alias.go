package router

import (
    "io"

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
var DefaultWriter = &gin.DefaultWriter

// 默认错误写入
var DefaultErrorWriter = &gin.DefaultErrorWriter

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

// ===== gin 默认方法 =====

// 使用 gin
// gin.New() *Engine
var New = gin.New

// 默认 gin
// gin.Default() *Engine
var Default = gin.Default

// 设置模式
// gin.SetMode(value string)
var SetMode = gin.SetMode

// DisableBindValidation closes the default validator.
// gin.DisableBindValidation()
var DisableBindValidation = gin.DisableBindValidation

// gin.EnableJsonDecoderUseNumber()
var EnableJsonDecoderUseNumber = gin.EnableJsonDecoderUseNumber

// gin.EnableJsonDecoderDisallowUnknownFields()
var EnableJsonDecoderDisallowUnknownFields = gin.EnableJsonDecoderDisallowUnknownFields

// Mode returns currently gin mode.
// gin.Mode() string
var Mode = gin.Mode

// gin.Bind(val any) HandlerFunc
var Bind = gin.Bind

// gin.WrapF(f http.HandlerFunc) HandlerFunc
var WrapF = gin.WrapF

// gin.WrapH(h http.Handler) HandlerFunc
var WrapH = gin.WrapH

// 文件夹
// gin.Dir(root string, listDirectory bool) http.FileSystem
var Dir = gin.Dir

// 是否为调试
// gin.IsDebugging() bool
var IsDebugging = gin.IsDebugging

// gin 默认回收中间件
// gin.Recovery() HandlerFunc
var Recovery = gin.Recovery

// gin.CustomRecovery(handle RecoveryFunc) HandlerFunc
var CustomRecovery = gin.CustomRecovery

// gin.RecoveryWithWriter(out io.Writer, recovery ...RecoveryFunc) HandlerFunc
var RecoveryWithWriter = gin.RecoveryWithWriter

// gin.CustomRecoveryWithWriter(out io.Writer, handle RecoveryFunc) HandlerFunc
var CustomRecoveryWithWriter = gin.CustomRecoveryWithWriter

// gin 默认日志中间件
// gin.Logger() HandlerFunc
var Logger = gin.Logger

// DisableConsoleColor disables color output in the console.
// gin.DisableConsoleColor()
var DisableConsoleColor = gin.DisableConsoleColor

// gin.ForceConsoleColor()
var ForceConsoleColor = gin.ForceConsoleColor

// ErrorLogger returns a handlerfunc for any error type.
// gin.ErrorLogger() HandlerFunc
var ErrorLogger = gin.ErrorLogger

// gin.ErrorLoggerT(typ ErrorType) HandlerFunc
var ErrorLoggerT = gin.ErrorLoggerT

// gin.LoggerWithFormatter(f LogFormatter) HandlerFunc
var LoggerWithFormatter = gin.LoggerWithFormatter

// gin.LoggerWithWriter(out io.Writer, notlogged ...string) HandlerFunc
var LoggerWithWriter = gin.LoggerWithWriter

// gin.LoggerWithConfig(conf LoggerConfig) HandlerFunc
var LoggerWithConfig = gin.LoggerWithConfig

// gin.BasicAuthForRealm(accounts Accounts, realm string) HandlerFunc
var BasicAuthForRealm = gin.BasicAuthForRealm

// gin.BasicAuth(accounts Accounts) HandlerFunc
var BasicAuth = gin.BasicAuth

// binding.Default(method, contentType string) Binding
var BindingDefault = binding.Default

// 设置默认写入
func WithDefaultWriter(writer io.Writer) {
    gin.DefaultWriter = writer
}

// 设置默认错误写入
func WithDefaultErrorWriter(writer io.Writer) {
    gin.DefaultErrorWriter = writer
}
