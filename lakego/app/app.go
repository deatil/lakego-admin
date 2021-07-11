package app

import (
    "sync"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/config"
    providerInterface "lakego-admin/lakego/provider/interfaces"
)

var serviceProviderLock = new(sync.RWMutex)

var serviceProvider = []func() providerInterface.ServiceProvider{}

var usedServiceProvider []providerInterface.ServiceProvider

/**
 * App结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type App struct {
    Engine *gin.Engine
}

func New() *App {
    return &App{}
}

func (app *App) Run() {
    // 加载 app
    app.loadApp()
}

// 注册服务提供者
func (app *App) Register(f func() providerInterface.ServiceProvider) {
    serviceProviderLock.Lock()
    defer serviceProviderLock.Unlock()

    serviceProvider = append(serviceProvider, f)
}

// 加载服务提供者
func (app *App) loadServiceProvider() {
    if len(serviceProvider) > 0 {
        for _, provider := range serviceProvider {
            p := provider()

            // 绑定 app 结构体
            p.WithApp(app)

            // 路由
            p.WithRoute(app.Engine)

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

// 加载 app
func (app *App) loadApp() {
    // 模式
    mode := config.New("admin").GetString("Mode")
    if mode != "dev" {
        gin.SetMode(gin.ReleaseMode)
    }

    // 路由
    r := gin.Default()

    app.Engine = r

    // 加载服务提供者
    app.loadServiceProvider()

    // 运行端口
    httpPort := config.New("server").GetString("Port")
    r.Run(httpPort)
}
