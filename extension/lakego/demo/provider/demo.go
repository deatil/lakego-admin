package provider

import (
    "fmt"

    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak/lakego/facade"
    "github.com/deatil/lakego-doak/lakego/provider"

    admin_route "github.com/deatil/lakego-doak-admin/admin/support/route"

    iapp "github.com/deatil/lakego-doak/lakego/app/interfaces"
    "github.com/deatil/lakego-doak-extension/extension/extension"

    demo_route "extension/lakego/demo/route"
)

/**
 * 服务提供者
 *
 * @create 2023-6-28
 * @author deatil
 */
type Demo struct {
    provider.ServiceProvider
}

// 引导
func (this *Demo) Register() {
    // 导入扩展
    this.loadExtInfo()
}

// 引导
func (this *Demo) Boot() {
    // Boot
}

// 导入路由
func (this *Demo) loadRoute() {
    // 后台路由，包括后台使用的所有中间件
    admin_route.AddRoute(func(engine *gin.RouterGroup) {
        demo_route.AdminRoute(engine)
    })

    // 常规 gin 路由，除 gin 自带外没有任何中间件
    this.AddRoute(func(engine *gin.Engine) {
        demo_route.GinRoute(engine)
    })
}

// 导入扩展
func (this *Demo) loadExtInfo() {
    // 加载前
    extension.Booting(func() {
        facade.Logger.Error("demo Booting")
    })

    // 加载后
    extension.Booted(func() {
        facade.Logger.Error("demo Booted")
    })

    slug := "lakego-admin.ext.demo"

    extension.Extend(extension.Extension{
        Name: "lakego.demo",
        Title: "扩展示例",
        Description: "扩展示例",
        Keywords: []string{
            "扩展示例",
        },
        Homepage: "https://github.com/deatil/lakego-admin",
        Authors: []extension.Author{
            {
                Name: "deatil",
                Email: "deatil@github.com",
                Homepage: "https://github.com/deatil",
            },
        },
        Version: "1.0.1",
        Adaptation: ">= 1.2.1",
        Install: func() error {
            facade.Logger.Error("demo Install")

            rules := getRules(slug)
            extension.NewRule().Create(rules, "0")

            return nil
        },
        Uninstall: func() error {
            facade.Logger.Error("demo Uninstall")

            extension.NewRule().Delete(slug)

            return nil
        },
        Upgrade: func() error {
            facade.Logger.Error("demo Upgrade")

            return nil
        },
        Enable: func() error {
            facade.Logger.Error("demo Enable")

            extension.NewRule().Enable(slug)

            return nil
        },
        Disable: func() error {
            facade.Logger.Error("demo Disable")

            extension.NewRule().Disable(slug)

            return nil
        },
        // 扩展启用后
        Start: func(app iapp.App) error {
            fmt.Println("demo Start")

            facade.Logger.Error("demo Start")

            // 导入路由
            this.loadRoute()

            return nil
        },
    })
}

func getRules(slug string) map[string]any {
    rules := map[string]any{
        "title": "Demo数据",
        "url": "#",
        "method": "OPTIONS",
        "slug": slug,
        "description": "示例扩展",
        "children": []map[string]any{
            {
                "title": "数据列表",
                "url": "demo",
                "method": "GET",
                "slug": "lakego-admin.ext.demo-index",
                "description": "数据列表",
            },
            {
                "title": "数据详情",
                "url": "demo/:id",
                "method": "GET",
                "slug": "lakego-admin.ext.demo-detail",
                "description": "数据详情",
            },
            {
                "title": "删除数据",
                "url": "demo/:id",
                "method": "DELETE",
                "slug": "lakego-admin.ext.demo-delete",
                "description": "删除数据",
            },
        },
    }

    return rules
}
