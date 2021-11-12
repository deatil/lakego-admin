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

    "github.com/deatil/lakego-admin/lakego/di"
    "github.com/deatil/lakego-admin/lakego/jwt"
    "github.com/deatil/lakego-admin/lakego/route"
    "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/support/path"
    "github.com/deatil/lakego-admin/lakego/middleware/event"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    routerFacade "github.com/deatil/lakego-admin/lakego/facade/router"
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
    RouteEngine *router.Engine

    // 根脚本
    RootCmd *command.Command

    // 启动前
    BootingCallbacks []func()

    // 启动后
    BootedCallbacks []func()

    // 自定义运行监听
    NetListener net.Listener
}

// 运行
func (this *App) Run() {
    // 初始化容器
    this.initDI()

    // 运行
    this.runApp()
}

// 注册服务提供者
func (this *App) Register(f func() providerInterface.ServiceProvider) {
    this.Lock.Lock()
    defer this.Lock.Unlock()

    this.ServiceProviders = append(this.ServiceProviders, f)

    // 启动后注册，直接注册
    if this.Runned {
        p := f()

        // 绑定 App 结构体
        p.WithApp(this)

        // 路由
        p.WithRoute(this.RouteEngine)

        // 注册
        p.Register()

        // 引导
        this.BootService(p)
    }
}

// 批量导入
func (this *App) Registers(providers []func() providerInterface.ServiceProvider) {
    if len(providers) > 0 {
        for _, provider := range providers {
            this.Register(provider)
        }
    }
}

// 加载服务提供者
func (this *App) loadServiceProvider() {
    if len(this.ServiceProviders) > 0 {
        for _, provider := range this.ServiceProviders {
            p := provider()

            // 绑定 App 结构体
            p.WithApp(this)

            // 路由
            p.WithRoute(this.RouteEngine)

            p.Register()

            this.UsedServiceProviders = append(this.UsedServiceProviders, p)
        }
    }

    // 启动前
    this.CallBootingCallbacks()

    if len(this.UsedServiceProviders) > 0 {
        for _, sp := range this.UsedServiceProviders {
            this.BootService(sp)
        }
    }

    // 启动后
    this.CallBootedCallbacks()
}

// 引导服务
func (this *App) BootService(s providerInterface.ServiceProvider) {
    s.CallBootingCallback()

    // 启动
    s.Boot()

    s.CallBootedCallback()
}

// 设置启动前函数
func (this *App) WithBooting(f func()) {
    this.BootingCallbacks = append(this.BootingCallbacks, f)
}

// 设置启动后函数
func (this *App) WithBooted(f func()) {
    this.BootedCallbacks = append(this.BootedCallbacks, f)
}

// 启动前回调
func (this *App) CallBootingCallbacks() {
    for _, callback := range this.BootingCallbacks {
        callback()
    }
}

// 启动后回调
func (this *App) CallBootedCallbacks() {
    for _, callback := range this.BootedCallbacks {
        callback()
    }
}

// 设置根脚本
func (this *App) WithRootCmd(root *command.Command) {
    this.RootCmd = root
}

// 获取根脚本
func (this *App) GetRootCmd() *command.Command {
    return this.RootCmd
}

// 设置命令行状态
func (this *App) WithRunningInConsole(console bool) {
    this.RunInConsole = console
}

// 获取命令行状态
func (this *App) RunningInConsole() bool {
    return this.RunInConsole
}

// 设置自定义监听
func (this *App) WithNetListener(listener net.Listener) *App {
    this.NetListener = listener

    return this
}

// 初始化路由
func (this *App) runApp() {
    var r *router.Engine

    if !this.RunInConsole {
        // 模式
        mode := config.New("admin").GetString("Mode")
        if mode != "dev" {
            router.SetMode(router.ReleaseMode)

            // 路由
            r = router.New()

            // 使用默认处理机制
            r.Use(router.Recovery())
        } else {
            router.SetMode(router.DebugMode)

            // 路由
            r = router.Default()
        }
    } else {
        // 脚本取消调试模式
        router.SetMode(router.ReleaseMode)

        // 路由
        r = router.New()
    }

    // 设置默认日志记录
    // file, err := os.Create("./runtime/route.log")
    // router.DefaultWriter = file

    // 事件
    r.Use(event.Handler())

    // 全局中间件
    globalMiddlewares := routerFacade.GetGlobalMiddlewares()

    // 设置全局中间件
    r.Use(globalMiddlewares...)

    // 缓存路由信息
    route.New().With(r)

    // 绑定路由
    this.RouteEngine = r

    // 设置已启动
    this.Runned = true

    // 加载服务提供者
    this.loadServiceProvider()

    // 不是命令行运行
    if !this.RunInConsole {
        this.ServerRun()
    }
}

// 服务运行
func (this *App) ServerRun() {
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
                this.GraceRun(addr)
            } else {
                // gin 自带运行
                this.RouteEngine.Run(addr)
            }

        case "TLS":
            // 运行端口
            addr := conf.GetString("Types.TLS.Addr")

            certFile := conf.GetString("Types.TLS.CertFile")
            keyFile := conf.GetString("Types.TLS.KeyFile")

            // 格式化
            certFile = this.FormatPath(certFile)
            keyFile = this.FormatPath(keyFile)

            this.RouteEngine.RunTLS(addr, certFile, keyFile)

        case "Unix":
            // 文件
            file := conf.GetString("Types.Unix.File")

            // 格式化
            file = this.FormatPath(file)

            this.RouteEngine.RunUnix(file)

        case "Fd":
            // fd
            fd := conf.GetInt("Types.Fd.Fd")

            this.RouteEngine.RunFd(fd)

        case "NetListener":
            if this.NetListener != nil {
                this.RouteEngine.RunListener(this.NetListener)
            } else {
                // 监听
                typ := conf.GetString("Types.NetListener.Type")
                addr := conf.GetString("Types.NetListener.Addr")

                netListener, _ := net.Listen(typ, addr)

                this.RouteEngine.RunListener(netListener)
            }

        default:
            panic("服务启动错误")
    }
}

// 优雅地关机
func (this *App) GraceRun(addr string) {
    srv := &http.Server{
        Addr:    addr,
        Handler: this.RouteEngine,
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

/**
 * 初始化容器
 */
func (this *App) initDI() {
    d := di.New()

    // 配置
    d.Provide(func() *config.Config {
        return config.New()
    })

    // jwt
    d.Provide(func() *jwt.JWT {
        return jwt.New()
    })
}

// 格式化文件路径
func (this *App) FormatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}
