package cmd

import (
    "fmt"
    "errors"

    "github.com/deatil/lakego-doak/lakego/command"

    "github.com/deatil/lakego-doak-extension/extension/service"
)

/**
 * 扩展管理
 *
 * > ./main lakego-admin:extension --action=[action] --name=[name]
 * > main.exe lakego-admin:extension --action=[action] --name=[name]
 * > go run main.go lakego-admin:extension --action=[action] --name=[name]
 *
 * > go run main.go lakego-admin:extension --action=local
 * > go run main.go lakego-admin:extension --action=inatll --name=lakego.demo
 * > go run main.go lakego-admin:extension --action=uninstall --name=lakego.demo
 * > go run main.go lakego-admin:extension --action=upgrade --name=lakego.demo
 * > go run main.go lakego-admin:extension --action=enable --name=lakego.demo
 * > go run main.go lakego-admin:extension --action=disable --name=lakego.demo
 * > go run main.go lakego-admin:extension --action=sort --name=lakego.demo --sort=105
 *
 * @create 2023-7-3
 * @author deatil
 */
var ExtensionCmd = &command.Command{
    Use: "lakego-admin:extension",
    Short: "lakego-admin extension ctl.",
    Example: "{execfile} lakego-admin:extension --action=[action] --name=[name]",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ExtensionCtl()
    },
}

var action string
var name string
var sort int

func init() {
    pf := ExtensionCmd.Flags()
    pf.StringVarP(&action, "action", "a", "", "操作类型")
    pf.StringVarP(&name, "name", "n", "", "扩展名称")
    pf.IntVarP(&sort, "sort", "s", 100, "扩展排序值")

    command.MarkFlagRequired(pf, "action")
}

// 重设权限
func ExtensionCtl() {
    if action == "" {
        fmt.Println("操作类型不能为空")
        return
    }

    switch name {
        case "inatll", "uninstall", "upgrade",
            "enable", "disable", "sort":
            if name == "" {
                fmt.Println("扩展名称不能为空")
                return
            }
    }

    err := errors.New("操作类型不存在")

    newExtension := service.NewExtension()

    switch action {
        case "local":
            exts := newExtension.Local()

            fmt.Println("本地扩展列表:")
            for i, ext := range exts {
                fmt.Println(fmt.Sprintf("%d: %s(%s)", i+1, ext["name"], ext["version"]))
            }

            return
        case "inatll":
            err = newExtension.Inatll(name)
            if err == nil {
                fmt.Println("安装扩展成功")
                return
            }
        case "uninstall":
            err = newExtension.Uninstall(name)
            if err == nil {
                fmt.Println("卸载扩展成功")
                return
            }
        case "upgrade":
            err = newExtension.Upgrade(name)
            if err == nil {
                fmt.Println("更新扩展成功")
                return
            }
        case "enable":
            err = newExtension.Enable(name)
            if err == nil {
                fmt.Println("启用扩展成功")
                return
            }
        case "disable":
            err = newExtension.Disable(name)
            if err == nil {
                fmt.Println("禁用扩展成功")
                return
            }
        case "sort":
            err = newExtension.Listorder(name, sort)
            if err == nil {
                fmt.Println("更新扩展排序成功")
                return
            }
    }

    fmt.Println(err.Error())
}

