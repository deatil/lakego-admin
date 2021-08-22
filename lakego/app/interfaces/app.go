package interfaces

import (
    "github.com/spf13/cobra"
    providerInterface "lakego-admin/lakego/provider/interfaces"
)

type App interface {
    // 注册服务提供者
    Register(func() providerInterface.ServiceProvider)

    // 获取脚本
    GetRootCmd() *cobra.Command
}
