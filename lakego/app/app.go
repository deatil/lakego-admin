package app

import (
    "sync"
    "github.com/spf13/cobra"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/config"
    "lakego-admin/lakego/middleware/event"
    providerInterface "lakego-admin/lakego/provider/interfaces"
)

var serviceProviderLock = new(sync.RWMutex)

var serviceProviders = []func() providerInterface.ServiceProvider{}

var usedServiceProvider []providerInterface.ServiceProvider

/**
 * App结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type App struct {
    // 运行状态
    Runned bool

    // 运行在命令行
    RunningInConsole bool

    // 路由
    RouteEngine *gin.Engine

    // 根脚本
    RootCmd *cobra.Command
}

func New() *App {
    return &App{
        Runned: false,
    }
}

func (app *App) Run() {
    // 加载 app
    app.loadApp()
}

// 注册服务提供者
func (app *App) Register(f func() providerInterface.ServiceProvider) {
    serviceProviderLock.Lock()
    defer serviceProviderLock.Unlock()

    serviceProviders = append(serviceProviders, f)

    // 启动后注册，直接注册
    if app.Runned {
        p := f()

        // 绑定 app 结构体
        p.WithApp(app)

        // 路由
        p.WithRoute(app.RouteEngine)

        p.Register()

        p.Boot()
    }
}

// 加载服务提供者
func (app *App) LoadServiceProvider() {
    if len(serviceProviders) > 0 {
        for _, provider := range serviceProviders {
            p := provider()

            // 绑定 app 结构体
            p.WithApp(app)

            // 路由
            p.WithRoute(app.RouteEngine)

            p.Register()

            usedServiceProvider = append(usedServiceProvider, p)
        }
    }

    if len(usedServiceProvider) > 0 {
        for _, p2 := range usedServiceProvider {
            p2.Boot()
        }
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
    app.RunningInConsole = console
}

// 获取命令行状态
func (app *App) GetRunningInConsole() bool {
    return app.RunningInConsole
}

// 加载 app
func (app *App) loadApp() {
    var r *gin.Engine

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

    // 事件
    r.Use(event.Handler())

    // 绑定路由
    app.RouteEngine = r

    // 加载服务提供者
    app.LoadServiceProvider()

    app.Runned = true

    // 运行端口
    httpPort := config.New("server").GetString("Port")
    r.Run(httpPort)
}
