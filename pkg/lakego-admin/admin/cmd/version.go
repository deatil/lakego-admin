package cmd

import (
    "fmt"

    "github.com/deatil/lakego-admin/lakego/color"
    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/facade/config"
)

/**
 * 系统信息
 *
 * > ./main lakego-admin:version
 * > main.exe lakego-admin:version
 * > go run main.go lakego-admin:version
 *
 * @create 2021-11-16
 * @author deatil
 */
var VersionCmd = &command.Command{
    Use: "lakego-admin:version",
    Short: "lakego-admin show version.",
    Example: "{execfile} lakego-admin:version",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ShowVersion()
    },
}

// 显示系统详情
func ShowVersion() {
    conf := config.New("version")

    name := conf.GetString("Name")
    nameMini := conf.GetString("NameMini")
    // logo := conf.GetString("Logo")
    release := conf.GetString("Release")
    version := conf.GetString("Version")

    fmt.Println(color.Green("lakego-admin 系统详情"))
    fmt.Println("系统名称：", color.Green(name))
    fmt.Println("系统简称：", color.Green(nameMini))
    fmt.Println("系统编译序号：", color.Green(release))
    fmt.Println("系统版本号：", color.Green(version))
}
