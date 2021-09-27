package cmd

import (
    "fmt"
    "regexp"
    "strings"

    "github.com/spf13/cobra"

    "lakego-admin/lakego/route"
    "lakego-admin/lakego/support/time"
    "lakego-admin/lakego/facade/config"

    "lakego-admin/admin/model"
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
var ImportRouteCmd = &cobra.Command{
    Use: "lakego-admin:import-route",
    Short: "lakego-admin import route'info.",
    Example: "{execfile} lakego-admin:import-route",
    SilenceUsage: true,
    PreRun: func(cmd *cobra.Command, args []string) {

    },
    Run: func(cmd *cobra.Command, args []string) {
        ImportRoute()
    },
}

// 导入路由信息
func ImportRoute() {
    routes := route.New().GetRoutes()

    // 路由前缀
    group := config.New("admin").GetString("Route.Prefix")

    for _, v := range routes {
        if !strings.HasPrefix(v.Path, "/" + group + "/") {
            continue
        }

        re, _ := regexp.Compile(`:[0-9a-zA-Z_\-\.\:]+`);
        authUrl := re.ReplaceAllString(v.Path, "*");
        authUrl = strings.TrimPrefix(authUrl, "/" + group)

        v.Path = strings.TrimPrefix(v.Path, "/" + group)

        result := map[string]interface{}{}
        err := model.NewAuthRule().
            Where("auth_url = ?", authUrl).
            First(&result).
            Error
        if err != nil || len(result) < 1 {
            insertData := model.AuthRule{
                Parentid: "0",
                Title: v.Path,
                Url: v.Path,
                Method: strings.ToUpper(v.Method),
                AuthUrl: authUrl,
                Slug: v.Path,
                Description: "",
                Listorder: "100",
                Status: 1,
                AddTime: time.NowTimeToInt(),
                AddIp: "127.0.0.1",
            }

            model.NewDB().Create(&insertData)
        } else {
            model.NewAuthRule().
                Where("auth_url = ?", authUrl).
                Updates(map[string]interface{}{
                    "url": v.Path,
                    "method": strings.ToUpper(v.Method),
                })
        }

    }

    fmt.Println("权限路由导入成功")
}

