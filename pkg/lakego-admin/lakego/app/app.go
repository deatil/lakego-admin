package app

import (
    "os"
    "os/signal"
    "net"
    "log"
    "sync"
    "time"
    "context"
    "net/http"

    "github.com/spf13/cobra"
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/route"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/middleware/event"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/facade/router"
    providerInterface "github.com/deatil/lakego-admin/lakego/provider/interfaces"
)

// App结构体
func New() *App {
    lock := new(sync.RWMutex)

    serviceProviders := make([]func() providerInterface.ServiceProvider, 0)

    usedServiceProviders := make([]providerInterface.ServiceProvider, 0)

    return &App{
        Lock: lock,
        ServiceProviders: serviceProviders,
        UsedServiceProviders: usedServiceProviders,
        Runned: false,
    }
}

/**
 * App结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type App struct {
    // 锁
    Lock *sync.RWMutex

    // 服务提供者
    ServiceProviders []func() providerInterface.ServiceProvider

    // 已使用服务提供者
    UsedServiceProviders []providerInterface.ServiceProvider

    // 运行状态
    Runned bool

    // 运行在命令行
    RunInConsole bool

    // 路由
    RouteEngine *gin.Engine

    // 根脚本
    RootCmd *cobra.Command

    // 启动前
    BootingCallbacks []func()

    // 启动后
    BootedCallbacks []func()

    // 自定义运行监听
    NetListener net.Listener
}

// 运行
func (app *App) Run() {
    // 运行
    app.runApp()
}

// 注册服务提供者
func (app *App) Register(f func() providerInterface.ServiceProvider) {
    app.Lock.Lock()
    defer app.Lock.Unlock()

    app.ServiceProviders = append(app.ServiceProviders, f)

    // 启动后注册，直接注册
    if app.Runned {
        p := f()

        // 绑定 app 结构体
        p.WithApp(app)

        // 路由
        p.WithRoute(app.RouteEngine)

        // 注册
        p.Register()

        // 引导
        app.BootService(p)
    }
}

// 批量导入
func (app *App) Registers(providers []func() providerInterface.ServiceProvider) {
    if len(providers) > 0 {
        for _, provider := range providers {
            app.Register(provider)
        }
    }
}

// 加载服务提供者
func (app *App) loadServiceProvider() {
    if len(app.ServiceProviders) > 0 {
        for _, provider := range app.ServiceProviders {
            p := provider()

            // 绑定 app 结构体
            p.WithApp(app)

            // 路由
            p.WithRoute(app.RouteEngine)

            p.Register()

            app.UsedServiceProviders = append(app.UsedServiceProviders, p)
        }
    }

    // 启动前
    app.CallBootingCallbacks()

    if len(app.UsedServiceProviders) > 0 {
        for _, sp := range app.UsedServiceProviders {
            app.BootService(sp)
        }
    }

    // 启动后
    app.CallBootedCallbacks()
}

// 引导服务
func (app *App) BootService(s providerInterface.ServiceProvider) {
    s.CallBootingCallback()

    // 启动
    s.Boot()

    s.CallBootedCallback()
}

// 设置启动前函数
func (app *App) WithBooting(f func()) {
    app.BootingCallbacks = append(app.BootingCallbacks, f)
}

// 设置启动后函数
func (app *App) WithBooted(f func()) {
    app.BootedCallbacks = append(app.BootedCallbacks, f)
}

// 启动前回调
func (app *App) CallBootingCallbacks() {
    for _, callback := range app.BootingCallbacks {
        callback()
    }
}

// 启动后回调
func (app *App) CallBootedCallbacks() {
    for _, callback := range app.BootedCallbacks {
        callback()
    }
}

// 设置根脚本
func (app *App) WithRootCmd(root *cobra.Command) {
    app.RootCmd = root
}

// 获取根脚本
func (app *App) GetRootCmd() *cobra.Command {
    return app.RootCmd
}

// 设置命令行状态
func (app *App) WithRunningInConsole(console bool) {
    app.RunInConsole = console
}

// 获取命令行状态
func (app *App) RunningInConsole() bool {
    return app.RunInConsole
}

// 设置自定义监听
func (app *App) WithNetListener(listener net.Listener) *App {
    app.NetListener = listener

    return app
}

// 初始化路由
func (app *App) runApp() {
    var r *gin.Engine

    if !app.RunInConsole {
        // 模式
        mode := config.New("admin").GetString("Mode")
        if mode != "dev" {
            gin.SetMode(gin.ReleaseMode)

            // 路由
            r = gin.New()

            // 使用默认处理机制
            r.Use(gin.Recovery())
        } else {
            gin.SetMode(gin.DebugMode)

            // 路由
            r = gin.Default()
        }
    } else {
        // 脚本取消调试模式
        gin.SetMode(gin.ReleaseMode)

        // 路由
        r = gin.New()
    }

    // 事件
    r.Use(event.Handler())

    // 全局中间件
    globalMiddlewares := router.GetGlobalMiddlewares()

    // 设置全局中间件
    r.Use(globalMiddlewares...)

    // 缓存路由信息
    route.New().With(r)

    // 绑定路由
    app.RouteEngine = r

    // 设置已启动
    app.Runned = true

    // 加载服务提供者
    app.loadServiceProvider()

    // 不是命令行运行
    if !app.RunInConsole {
        app.ServerRun()
    }
}

// 服务运行
func (app *App) ServerRun() {
    conf := config.New("server")

    // 运行方式
    runType := conf.GetString("Default")
    switch runType {
        case "Http":
            // 运行方式
            servertype := conf.GetString("Types.Http.Servertype")

            // 运行端口
            addr := conf.GetString("Types.Http.Addr")

            if servertype == "grace" {
                // 优雅地关机
                app.GraceRun(addr)
            } else {
                // gin 自带运行
                app.RouteEngine.Run(addr)
            }

        case "TLS":
            // 运行端口
            addr := conf.GetString("Types.TLS.Addr")

            certFile := conf.GetString("Types.TLS.CertFile")
            keyFile := conf.GetString("Types.TLS.KeyFile")

            // 格式化
            certFile = app.FormatPath(certFile)
            keyFile = app.FormatPath(keyFile)

            app.RouteEngine.RunTLS(addr, certFile, keyFile)

        case "Unix":
            // 文件
            file := conf.GetString("Types.Unix.File")

            // 格式化
            file = app.FormatPath(file)

            app.RouteEngine.RunUnix(file)

        case "Fd":
            // fd
            fd := conf.GetInt("Types.Fd.Fd")

            app.RouteEngine.RunFd(fd)

        case "NetListener":
            if app.NetListener != nil {
                app.RouteEngine.RunListener(app.NetListener)
            } else {
                // 监听
                typ := conf.GetString("Types.NetListener.Type")
                port := conf.GetString("Types.NetListener.Port")

                netListener, _ := net.Listen(typ, port)

                app.RouteEngine.RunListener(netListener)
            }

        default:
            panic("服务启动错误")
    }
}

// 优雅地关机
func (app *App) GraceRun(addr string) {
    srv := &http.Server{
        Addr:    addr,
        Handler: app.RouteEngine,
    }

    go func() {
        // 服务连接
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen: %s\n", err)
        }
    }()

    // 等待中断信号以优雅地关闭服务器（设置 5 秒的超时时间）
    quit := make(chan os.Signal)
    signal.Notify(quit, os.Interrupt)
    <-quit
    log.Println("Shutdown Server ...")

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server Shutdown:", err)
    }

    log.Println("Server exiting")
}

// 格式化文件路径
func (app *App) FormatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}
