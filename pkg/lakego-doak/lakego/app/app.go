package app

import (
    "os"
    "os/signal"
    "net"
    "net/http"
    "fmt"
    "log"
    "sync"
    "time"
    "context"

    "github.com/deatil/lakego-doak/lakego/di"
    "github.com/deatil/lakego-doak/lakego/jwt"
    "github.com/deatil/lakego-doak/lakego/env"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/support/path"
    timeTool "github.com/deatil/lakego-doak/lakego/support/time"
    "github.com/deatil/lakego-doak/lakego/middleware/event"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    routerFacade "github.com/deatil/lakego-doak/lakego/facade/router"
    providerInterface "github.com/deatil/lakego-doak/lakego/provider/interfaces"
)

// App结构体
func New() *App {
    return &App{
        Config: config.New("server"),
        Lock: new(sync.RWMutex),
        ServiceProviders: make(ServiceProviders, 0),
        UsedServiceProviders: make(UsedServiceProviders, 0),
        Runned: false,
    }
}

type (
    // 服务提供者
    ServiceProvider = func() providerInterface.ServiceProvider

    // 服务提供者列表
    ServiceProviders = []ServiceProvider

    // 已使用服务提供者
    UsedServiceProvider = providerInterface.ServiceProvider

    // 已使用服务提供者列表
    UsedServiceProviders = []UsedServiceProvider

    // 启动前
    BootingCallback = func()

    // 启动前列表
    BootingCallbacks = []BootingCallback

    // 启动后
    BootedCallback = func()

    // 启动后列表
    BootedCallbacks = []BootedCallback
)

/**
 * App结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type App struct {
    // 配置
    Config *config.Config

    // 锁
    Lock *sync.RWMutex

    // 服务提供者
    ServiceProviders ServiceProviders

    // 已使用服务提供者
    UsedServiceProviders UsedServiceProviders

    // 运行状态
    Runned bool

    // 运行在命令行
    RunInConsole bool

    // 路由
    RouteEngine *router.Engine

    // 根脚本
    RootCmd *command.Command

    // 启动前
    BootingCallbacks BootingCallbacks

    // 启动后
    BootedCallbacks BootedCallbacks

    // 自定义运行监听
    NetListener net.Listener
}

// 设置配置
func (this *App) WithConfig(conf *config.Config) *App {
    this.Config = conf

    return this
}

// 运行
func (this *App) Run() {
    // 导入环境变量
    this.LoadEnv()

    // 初始化容器
    this.initDI()

    // 运行
    this.runApp()
}

// 注册服务提供者
func (this *App) Register(f ServiceProvider) {
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
func (this *App) Registers(providers ServiceProviders) {
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
func (this *App) BootService(s UsedServiceProvider) {
    s.CallBootingCallback()

    // 启动
    s.Boot()

    s.CallBootedCallback()
}

// 设置启动前函数
func (this *App) WithBooting(f BootingCallback) {
    this.BootingCallbacks = append(this.BootingCallbacks, f)
}

// 设置启动后函数
func (this *App) WithBooted(f BootedCallback) {
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

// 是否为开发者模式
func (this *App) IsDev() bool {
    mode := this.Config.GetString("Mode")

    if mode == "dev" {
        return true
    } else {
        return false
    }
}

// 设置自定义监听
func (this *App) WithNetListener(listener net.Listener) *App {
    this.NetListener = listener

    return this
}

// 初始化路由
func (this *App) runApp() {
    var r *router.Engine

    // 配置
    serverConf := this.Config

    if !this.RunInConsole {
        mode := serverConf.GetString("Mode")

        // 模式
        if mode == "dev" {
            // 日志显示方式
            logShowType := serverConf.GetString("LogShowType")

            if logShowType == "lakego" {
                router.SetMode(router.DebugMode)

                // 路由
                r = router.New()

                r.Use(router.LoggerWithFormatter(func(param router.LogFormatterParams) string {
                    // 自定义格式
                    return fmt.Sprintf("[lakego-admin] %s - [%s] \"%s %s %s %d %s [%s] %s\"\n",
                        param.ClientIP,
                        param.TimeStamp.Format("2006-01-02 15:04:05"),
                        // param.TimeStamp.Format(time.RFC1123),
                        param.Method,
                        param.Path,
                        param.Request.Proto,
                        param.StatusCode,
                        param.Latency,
                        param.Request.UserAgent(),
                        param.ErrorMessage,
                    )
                }))

                // 使用默认处理机制
                r.Use(router.Recovery())
            } else {
                router.SetMode(router.DebugMode)

                // 路由
                r = router.Default()
            }
        } else {
            router.SetMode(router.ReleaseMode)

            // 路由
            r = router.New()

            // 使用默认处理机制
            r.Use(router.Recovery())
        }

    } else {
        // 脚本取消调试模式
        router.SetMode(router.ReleaseMode)

        // 路由
        r = router.New()
    }

    // 日志记录方式
    logType := serverConf.GetString("LogType")
    if logType == "file" {
        logFileName := timeTool.NowFormat("Ymd")
        logFile := path.RuntimePath(fmt.Sprintf("/log/route_%s.log", logFileName))

        // 设置默认日志记录
        file, err := os.Create(logFile)
        if err == nil {
            router.WithDefaultWriter(file)
        }
    }

    // 事件
    r.Use(event.Handler())

    // 全局中间件
    globalMiddlewares := routerFacade.GetGlobalMiddlewares()

    // 设置全局中间件
    r.Use(globalMiddlewares...)

    // 缓存路由信息
    router.NewRoute().With(r)

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
    conf := this.Config

    // 报错数据
    var err error

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
                err = this.RouteEngine.Run(addr)
            }

        case "TLS":
            // 运行端口
            addr := conf.GetString("Types.TLS.Addr")

            certFile := conf.GetString("Types.TLS.CertFile")
            keyFile := conf.GetString("Types.TLS.KeyFile")

            // 格式化
            certFile = this.FormatPath(certFile)
            keyFile = this.FormatPath(keyFile)

            err = this.RouteEngine.RunTLS(addr, certFile, keyFile)

        case "Unix":
            // 文件
            file := conf.GetString("Types.Unix.File")

            // 格式化
            file = this.FormatPath(file)

            err = this.RouteEngine.RunUnix(file)

        case "Fd":
            // fd
            fd := conf.GetInt("Types.Fd.Fd")

            err = this.RouteEngine.RunFd(fd)

        case "NetListener":
            if this.NetListener != nil {
                err = this.RouteEngine.RunListener(this.NetListener)
            } else {
                // 监听
                typ := conf.GetString("Types.NetListener.Type")
                addr := conf.GetString("Types.NetListener.Addr")

                netListener, _ := net.Listen(typ, addr)

                err = this.RouteEngine.RunListener(netListener)
            }

        default:
            panic("服务启动错误")
    }

    if err != nil {
        log.Fatalf("listen: %s\n", err)
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

// 导入 env 环境变量
func (this *App) LoadEnv() {
    // 开发方式 env 环境文件
    envType := ".env.production"

    mode := this.Config.GetString("Mode")
    if mode == "dev" {
        envType = ".env.development"
    }

    // 开发环境变量
    err := env.Load(envType)
    if err != nil {
        log.Println("环境变量导入失败，原因为：" + err.Error())
    }

    // 默认环境变量
    err = env.Load()
    if err != nil {
        log.Println("环境变量导入失败，原因为：" + err.Error())
    }
}

// 格式化文件路径
func (this *App) FormatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}
