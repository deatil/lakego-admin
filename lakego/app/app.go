package app

import (
	"sync"
	"github.com/gin-gonic/gin"
	
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/database"
	"lakego-admin/lakego/provider"
)

var serviceProviderLock = new(sync.RWMutex)

var ServiceProvider = []func() provider.ServiceProvider{}

var UsedServiceProvider []provider.ServiceProvider

/**
 * App结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type App struct {
	Engine *gin.Engine
}

func NewApp() *App {
	return &App{}
}

func (app *App) Run() {
	// 数据库
	app.loadDatabase()
	
	// 加载 app
	app.loadApp()	
} 

// 注册服务提供者
func (app *App) Register(f func() provider.ServiceProvider) {	
	serviceProviderLock.Lock()
	defer serviceProviderLock.Unlock()
	
	ServiceProvider = append(ServiceProvider, f)
}

// 加载服务提供者
func (app *App) loadServiceProvider() {	
	if len(ServiceProvider) > 0 {
		for _, provider := range ServiceProvider {
			p := provider()
			
			p.WithRoute(app.Engine) 
			
			p.Register() 
			
			UsedServiceProvider = append(UsedServiceProvider, p)
		}
	}
	
	if len(UsedServiceProvider) > 0 {
		for _, p2 := range UsedServiceProvider {
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

// orm
func (app *App) loadDatabase() {	
	database.GetPoolInstance().InitPool()
}
