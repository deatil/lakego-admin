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

            return nil
        },
        Uninstall: func() error {
            logger.New().Error("demo Uninstall")

            return nil
        },
        Upgrade: func() error {
            logger.New().Error("demo Upgrade")

            return nil
        },
        Enable: func() error {
            logger.New().Error("demo Enable")

            return nil
        },
        Disable: func() error {
            logger.New().Error("demo Disable")

            return nil
        },
        Start: func(i iapp.App) error {
            fmt.Println("demo starting")

            logger.New().Error("demo starting")

            return nil
        },
    })
}
