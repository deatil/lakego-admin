package cmd

import (
    "fmt"
    "strings"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/config"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

/**
 * 导入路由信息
 *
 * > ./main lakego-admin:import-route
 * > main.exe lakego-admin:import-route
 * > go run main.go lakego-admin:import-route
 *
 * @create 2021-9-26
 * @author deatil
 */
var ImportRouteCmd = &command.Command{
    Use: "lakego-admin:import-route",
    Short: "lakego-admin import route'info.",
    Example: "{execfile} lakego-admin:import-route",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ImportRoute()
    },
}

// 导入路由信息
func ImportRoute() {
    routes := router.DefaultRoute().GetRoutes()

    // 路由前缀
    group := config.New("admin").GetString("Route.Prefix")

    for _, v := range routes {
        if !strings.HasPrefix(v.Path, "/" + group + "/") {
            continue
        }

        /*
        re, _ := regexp.Compile(`:[0-9a-zA-Z_\-\.\:]+`);
        authUrl := re.ReplaceAllString(v.Path, "*");
        authUrl = strings.TrimPrefix(authUrl, "/" + group)
        */

        v.Path = strings.TrimPrefix(v.Path, "/" + group)

        result := map[string]any{}
        err := model.NewAuthRule().
            Where("url = ?", v.Path).
            First(&result).
            Error
        if err != nil || len(result) < 1 {
            insertData := model.AuthRule{
                Parentid: "0",
                Title: v.Path,
                Url: v.Path,
                Method: strings.ToUpper(v.Method),
                Slug: v.Path,
                Description: "",
                Listorder: 100,
                Status: 1,
                AddTime: int(datebin.NowTimestamp()),
                AddIp: "127.0.0.1",
            }

            model.NewDB().Create(&insertData)
        } else {
            model.NewAuthRule().
                Where("url = ?", v.Path).
                Where("method = ?", strings.ToUpper(v.Method)).
                Updates(map[string]any{
                    "title": v.Path,
                })
        }

    }

    fmt.Println("权限路由导入成功")
}

