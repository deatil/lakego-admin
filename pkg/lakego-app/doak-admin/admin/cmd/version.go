package cmd

import (
    "fmt"
    "runtime"

    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade"
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
    conf := facade.Config("version")

    name := conf.GetString("name")
    nameMini := conf.GetString("name-mini")
    // logo := conf.GetString("Logo")
    release := conf.GetString("release")
    version := conf.GetString("version")

    goVersion := runtime.Version()

    serverUrl := facade.Config("server").GetString("server-url")

    color.Magenta("\n===========================\n")

    logo := `
.__          __
|  | _____  |  | __ ____   ____   ____
|  | \__  \ |  |/ // __ \ / ___\ /  _ \
|  |__/ __ \|    <\  ___// /_/  >  <_> )
|____(____  /__|_ \\___  >___  / \____/
          \/     \/    \/_____/
    `

    color.Whiteln(logo);

    color.Yellow("\nlakego-admin 系统详情\n\n")

    color.Cyan("系统名称：");
    fmt.Println(name);

    color.Cyan("系统简称：");
    fmt.Println(nameMini);

    color.Cyan("编译序号：");
    fmt.Println(release);

    color.Cyan("版本序号：");
    fmt.Println(version);

    color.Cyan("Go  版本：");
    fmt.Println(goVersion);

    color.Cyan("运行地址：");
    fmt.Println(serverUrl);

    color.Magenta("\n===========================\n")
}
