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

    color.Magenta("\n===========================\n")

    color.Yellow("\nlakego-admin 系统详情\n\n")

    color.Cyan("系统名称：");
    fmt.Println(name);

    color.Cyan("系统简称：");
    fmt.Println(nameMini);

    color.Cyan("编译序号：");
    fmt.Println(release);

    color.Cyan("版本序号：");
    fmt.Println(version);

    color.Magenta("\n===========================\n")
}
