package cmd

import (
    "fmt"
    "strings"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/go-encoding/encoding"
    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/command"

    "github.com/deatil/lakego-doak-admin/admin/model"
)

/**
 * 导入 swagger api路由信息
 *
 * > ./main lakego-admin:import-apiroute
 * > main.exe lakego-admin:import-apiroute
 * > go run main.go lakego-admin:import-apiroute
 *
 * @create 2021-9-26
 * @author deatil
 */
var ImportApiRouteCmd = &command.Command{
    Use: "lakego-admin:import-apiroute",
    Short: "lakego-admin import apiroute'info.",
    Example: "{execfile} lakego-admin:import-apiroute",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {

    },
    Run: func(cmd *command.Command, args []string) {
        ImportApiRoute()
    },
}

// 导入路由信息
func ImportApiRoute() {
    fs := filesystem.New()

    // api 文件
    swaggerFile := "./docs/swagger/swagger.json"
    swaggerInfo, err := fs.Get(swaggerFile)
    if err != nil {
        fmt.Println("[swagger.json] 文件不存在")
        return
    }

    var routes map[string]interface{}

    // 转换为 map
    err = encoding.Unmarshal([]byte(swaggerInfo), &routes)
    if err != nil {
        fmt.Println("api 信息错误")
        return
    }

    if _, ok := routes["paths"]; !ok {
        fmt.Println("api 路由信息不存在")
        return
    }

    paths := routes["paths"].(map[string]interface{})

    for k, v := range paths {
        result := map[string]interface{}{}

        paths2 := v.(map[string]interface{})
        for kk, vv := range paths2 {
            url := k
            method := strings.ToUpper(kk)

            data := vv.(map[string]interface{})
            title := data["summary"].(string)

            err := model.NewAuthRule().
                Where("url = ?", url).
                Where("method = ?", method).
                First(&result).
                Error
            if err != nil || len(result) < 1 {
                insertData := model.AuthRule{
                    Parentid: "0",
                    Title: title,
                    Url: url,
                    Method: method,
                    Slug: url,
                    Description: "",
                    Listorder: "100",
                    Status: 1,
                    AddTime: int(datebin.NowTime()),
                    AddIp: "127.0.0.1",
                }

                model.NewDB().Create(&insertData)
            } else {
                model.NewAuthRule().
                    Where("url = ?", url).
                    Where("method = ?", method).
                    Updates(map[string]interface{}{
                        "url": url,
                        "method": method,
                    })
            }

        }

    }

    fmt.Println("权限路由导入成功")
}

