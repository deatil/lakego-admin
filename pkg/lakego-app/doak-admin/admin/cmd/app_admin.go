package cmd

import (
    "fmt"

    "github.com/deatil/lakego-doak/lakego/str"
    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"

    "github.com/deatil/lakego-doak-admin/admin/stubs"
)

/**
 * 脚手架
 *
 * > ./main lakego-admin:app-admin --type=[type] --name=[name] [--force]
 * > main.exe lakego-admin:app-admin --type=[type] --name=[name] [--force]
 * > go run main.go lakego-admin:app-admin --type=[type] --name=[name] [--force]
 *
 * > go run main.go lakego-admin:app-admin --type=create_controller --name=HotBook
 * > go run main.go lakego-admin:app-admin --type=create_model --name=HotBook
 *
 * @create 2022-12-12
 * @author deatil
 */
var AppAdminCmd = &command.Command{
    Use: "lakego-admin:app-admin",
    Short: "lakego-admin app-admin.",
    Example: "{execfile} lakego-admin:app-admin --type=[type] --name=[name]",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        AppAdmin()
    },
}

var typ string
var name string
var force bool

func init() {
    pf := AppAdminCmd.Flags()
    pf.StringVarP(&typ, "type", "t", "", "类型")
    pf.StringVarP(&name, "name", "n", "", "名称")
    pf.BoolVarP(&force, "force", "f", false, "是否覆盖")

    command.MarkFlagRequired(pf, "type")
    command.MarkFlagRequired(pf, "name")
}

// 脚手架
func AppAdmin() {
    if typ == "" {
        fmt.Println("操作类型不能为空！")
        return
    }

    switch typ {
        case "create_controller":
            makeController()
        case "create_model":
            makeModel()
        default:
            fmt.Println("操作类型没有实现！")
    }
}

// 生成控制器
func makeController() {
    if name == "" {
        color.Red("控制器名称不能为空！\n")
        return
    }

    data := map[string]string{
        "controllerName": str.Camel(name),
        "controllerLowerName": str.LowerCamel(name),
        "controllerPath": str.Kebab(name),
    }

    name = str.Snake(name)

    err := stubs.New().MakeController(name, data, force)
    if err != nil {
        color.Red("生成控制器失败！原因为：" + err.Error() + "\n")
        return
    }

    color.Green("生成控制器成功！\n")
}

// 生成模型
func makeModel() {
    if name == "" {
        color.Red("模型名称不能为空！\n")
        return
    }

    data := map[string]string{
        "modelName": str.Camel(name),
    }

    name = str.Snake(name)

    err := stubs.New().MakeModel(name, data, force)
    if err != nil {
        color.Red("生成模型失败！原因为：" + err.Error() + "\n")
        return
    }

    color.Green("生成模型成功！\n")
}
