package provider

import (
    "fmt"

    "github.com/deatil/lakego-doak/lakego/provider"
    "github.com/deatil/lakego-doak/lakego/facade/logger"

    iapp "github.com/deatil/lakego-doak/lakego/app/interfaces"
    "github.com/deatil/lakego-doak-extension/extension/extension"
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
    // todo
}

// 导入扩展
func (this *Demo) loadExtInfo() {
    slug := "lakego-admin.ext.demo"

    extension.Extend(extension.Extension{
        Name: "deatil.demo",
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
            logger.New().Error("demo Install")

            rules := getRules(slug)
            extension.NewRule().Create(rules, "0")

            return nil
        },
        Uninstall: func() error {
            logger.New().Error("demo Uninstall")

            extension.NewRule().Delete(slug)

            return nil
        },
        Upgrade: func() error {
            logger.New().Error("demo Upgrade")

            return nil
        },
        Enable: func() error {
            logger.New().Error("demo Enable")

            extension.NewRule().Enable(slug)

            return nil
        },
        Disable: func() error {
            logger.New().Error("demo Disable")

            extension.NewRule().Disable(slug)

            return nil
        },
        Start: func(i iapp.App) error {
            fmt.Println("demo starting")

            logger.New().Error("demo starting")

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
