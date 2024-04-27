package app

import (
    "os"
    "os/signal"
    "net"
    "net/http"
    "fmt"
    "log"
    "sync"
    "errors"
    "context"
    "reflect"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-jwt/jwt"
    "github.com/deatil/lakego-doak/lakego/di"
    "github.com/deatil/lakego-doak/lakego/env"
    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/schedule"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/middleware/recovery"
    iprovider "github.com/deatil/lakego-doak/lakego/provider/interfaces"
)

// 计划任务接口
type ServiceProviderSchedule interface {
    Schedule(*schedule.Schedule)
}

/**
 * App结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type App struct {
    // 锁
    mut sync.RWMutex

    // 配置
    config *config.Config

    // 开发者模式
    dev bool

    // 服务提供者
    serviceProviders []iprovider.ServiceProvider

    // 已经加载的服务提供者
    loadedProviders map[string]bool

    // 运行状态
    runned bool

    // 运行在命令行
    runningInConsole bool

    // 路由
    route *router.Engine

    // 根脚本
    rootCmd *command.Command

    // 计划任务
    schedule *schedule.Schedule

    // 启动前
    bootingCallbacks []func()

    // 启动后
    bootedCallbacks []func()

    // 自定义运行监听
    netListener net.Listener
}

// App 结构体
func New() *App {
    cfg := config.New("server")

    // 开发者模式
    var dev bool
    mode := cfg.GetString("mode")
    if mode == "dev" {
        dev = true
    } else {
        dev = false
    }

    // 计划任务
    scheduler := schedule.New().SetShowLogInfo(dev)

    return &App{
        dev:              dev,
        runned:           false,
        config:           cfg,
        schedule:         scheduler,
        serviceProviders: make([]iprovider.ServiceProvider, 0),
        loadedProviders:  make(map[string]bool),
    }
}

// 设置配置
func (this *App) WithConfig(conf *config.Config) *App {
    this.config = conf

    return this
}

// 运行
func (this *App) Run() {
    // 导入环境变量
    this.loadEnv()

    // 初始化容器
    this.initDI()

    // 运行
    this.runApp()
}

// 注册服务提供者
func (this *App) Register(f func() iprovider.ServiceProvider) iprovider.ServiceProvider {
    p := f()

    if sp := this.GetRegister(p); sp != nil {
        return sp
    }

    this.markAsRegistered(p)

    // 启动后注册，直接注册
    if this.runned {
        // 绑定 App 结构体
        p.WithApp(this)

        // 路由
        p.WithRoute(this.route)

        // 注册
        p.Register()

        // 添加计划任务
        if ps, ok := p.(ServiceProviderSchedule); ok {
            ps.Schedule(this.schedule)
        }

        // 引导
        this.BootService(p)
    }

    return p
}

// 批量导入
func (this *App) Registers(providers []func() iprovider.ServiceProvider) {
    for _, provider := range providers {
        this.Register(provider)
    }
}

// 注册
func (this *App) markAsRegistered(provider iprovider.ServiceProvider) {
    this.mut.Lock()
    defer this.mut.Unlock()

    this.serviceProviders = append(this.serviceProviders, provider)

    this.loadedProviders[this.GetProviderName(provider)] = true
}

// GetLoadedProviders
func (this *App) GetLoadedProviders() map[string]bool {
    return this.loadedProviders
}

// ProviderIsLoaded
func (this *App) ProviderIsLoaded(provider string) bool {
    this.mut.RLock()
    defer this.mut.RUnlock()

    if _, ok := this.loadedProviders[provider]; ok {
        return true
    }

    return false
}

// 反射获取服务提供者名称
func (this *App) GetProviderName(provider any) (name string) {
    p := reflect.TypeOf(provider)

    if p.Kind() == reflect.Pointer {
        p = p.Elem()
        name = "*"
    }

    pkgPath := p.PkgPath()

    if pkgPath != "" {
        name += pkgPath + "."
    }

    return name + p.Name()
}

// 获取注册的服务提供者
func (this *App) GetRegister(p any) iprovider.ServiceProvider {
    var name string

    switch t := p.(type) {
        case iprovider.ServiceProvider:
            name = this.GetProviderName(t)
        case string:
            name = t
    }

    if name != "" {
        for _, sp := range this.serviceProviders {
            if this.GetProviderName(sp) == name {
                return sp
            }
        }
    }

    return nil
}

// 引导服务
func (this *App) BootService(s iprovider.ServiceProvider) {
    s.CallBootingCallback()

    // 启动
    s.Boot()

    s.CallBootedCallback()
}

// 设置启动前函数
func (this *App) WithBooting(f func()) {
    this.mut.Lock()
    defer this.mut.Unlock()

    this.bootingCallbacks = append(this.bootingCallbacks, f)
}

// 设置启动后函数
func (this *App) WithBooted(f func()) {
    this.mut.Lock()
    defer this.mut.Unlock()

    this.bootedCallbacks = append(this.bootedCallbacks, f)
}

// 启动前回调
func (this *App) CallBootingCallbacks() {
    for _, callback := range this.bootingCallbacks {
        callback()
    }
}

// 启动后回调
func (this *App) CallBootedCallbacks() {
    for _, callback := range this.bootedCallbacks {
        callback()
    }
}

// 设置根脚本
func (this *App) WithRootCmd(cmd *command.Command) {
    this.rootCmd = cmd
}

// 获取根脚本
func (this *App) GetRootCmd() *command.Command {
    return this.rootCmd
}

// 设置计划任务
func (this *App) WithSchedule(cron *schedule.Schedule) {
    this.schedule = cron
}

// 获取计划任务
func (this *App) GetSchedule() *schedule.Schedule {
    return this.schedule
}

// 设置命令行状态
func (this *App) WithRunningInConsole(console bool) {
    this.runningInConsole = console
}

// 获取命令行状态
func (this *App) RunningInConsole() bool {
    return this.runningInConsole
}

// 是否为已运行
func (this *App) IsRunned() bool {
    return this.runned
}

// 是否为开发者模式
func (this *App) IsDev() bool {
    return this.dev
}

// 设置自定义监听
func (this *App) WithNetListener(listener net.Listener) *App {
    this.netListener = listener

    return this
}

// ==================

// 初始化路由
func (this *App) runApp() {
    var r *router.Engine

    // 配置
    serverConf := this.config

    if !this.runningInConsole {
        mode := serverConf.GetString("mode")

        // 模式
        if mode == "dev" {
            // 日志显示方式
            logShowType := serverConf.GetString("log-show-type")

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
    logType := serverConf.GetString("log-type")
    if logType == "file" {
        logFileName := datebin.Now().Format("Ymd")
        logFile := path.RuntimePath(fmt.Sprintf("/log/route_%s.log", logFileName))

        // 设置默认日志记录
        file, err := os.Create(logFile)
        if err == nil {
            router.WithDefaultWriter(file)
        }
    }

    // 全局中间件
    r.Use(recovery.Handler())

    // 缓存路由信息
    router.NewRoute().With(r)

    // 绑定路由
    this.route = r

    // 设置已启动
    this.runned = true

    // 加载服务提供者
    this.loadServiceProvider()

    // 全局中间件
    globalMiddlewares := router.GetGlobalMiddlewares()

    // 设置全局中间件
    r.Use(globalMiddlewares...)

    // 不是命令行运行
    if !this.runningInConsole {
        this.serverRun()
    }
}

// 加载服务提供者
func (this *App) loadServiceProvider() {
    usedServiceProviders := make([]iprovider.ServiceProvider, 0)

    for _, p := range this.serviceProviders {
        // 绑定 App 结构体
        p.WithApp(this)

        // 路由
        p.WithRoute(this.route)

        p.Register()

        // 添加计划任务
        if ps, ok := p.(ServiceProviderSchedule); ok {
            ps.Schedule(this.schedule)
        }

        usedServiceProviders = append(usedServiceProviders, p)
    }

    // 启动前
    this.CallBootingCallbacks()

    for _, sp := range usedServiceProviders {
        this.BootService(sp)
    }

    // 启动后
    this.CallBootedCallbacks()
}

// 服务运行
func (this *App) serverRun() {
    conf := this.config

    // 报错数据
    var err error

    // 运行方式
    runType := conf.GetString("default")
    switch runType {
        case "http":
            // 运行方式
            servertype := conf.GetString("types.http.server-type")

            // 运行端口
            addr := conf.GetString("types.http.addr")

            if servertype == "grace" {
                // 优雅地关机
                this.graceRun(addr)
            } else {
                // gin 自带运行
                err = this.route.Run(addr)
            }

        case "tls":
            // 运行端口
            addr := conf.GetString("types.tls.addr")

            certFile := conf.GetString("types.tls.cert-file")
            keyFile := conf.GetString("types.tls.key-file")

            // 格式化
            certFile = this.formatPath(certFile)
            keyFile = this.formatPath(keyFile)

            err = this.route.RunTLS(addr, certFile, keyFile)

        case "unix":
            // 文件
            file := conf.GetString("types.unix.file")

            // 格式化
            file = this.formatPath(file)

            err = this.route.RunUnix(file)

        case "fd":
            // fd
            fd := conf.GetInt("types.fd.fd")

            err = this.route.RunFd(fd)

        case "net-listener":
            if this.netListener != nil {
                err = this.route.RunListener(this.netListener)
            } else {
                // 监听
                typ := conf.GetString("types.net-listener.type")
                addr := conf.GetString("types.net-listener.addr")

                netListener, _ := net.Listen(typ, addr)

                err = this.route.RunListener(netListener)
            }

        default:
            err = errors.New("服务启动错误")
    }

    if err != nil {
        log.Fatalf("server err: %s\n", err)
    }
}

// 优雅地关机
func (this *App) graceRun(address string) {
    conf := this.config

    srv := &http.Server{
        Addr:           address,
        Handler:        this.route,
        ReadTimeout:    conf.GetDuration("types.http.grace-read-timeout"),
        WriteTimeout:   conf.GetDuration("types.http.grace-write-timeout"),
        MaxHeaderBytes: 1 << 20,
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

    ctx, cancel := context.WithTimeout(context.Background(), conf.GetDuration("types.http.grace-timeout"))
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

    // jwt
    d.Provide(func() *jwt.JWT {
        return jwt.New()
    })
}

// 导入 env 环境变量
func (this *App) loadEnv() {
    // 环境变量
    err := env.Load()
    if err != nil {
        log.Println("环境变量导入失败，原因为：" + err.Error())
    }
}

// 格式化文件路径
func (this *App) formatPath(file string) string {
    filename := path.FormatPath(file)

    return filename
}
