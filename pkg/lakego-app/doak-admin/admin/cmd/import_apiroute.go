package cmd

import (
    "fmt"
    "strings"

    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/go-encoding/encoding"
    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/array"
    "github.com/deatil/lakego-doak/lakego/random"
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
    swaggerFile := "./swagger/swagger.json"
    swaggerInfo, err := fs.Get(swaggerFile)
    if err != nil {
        fmt.Println("[swagger.json] 文件不存在")
        return
    }

    var routes map[string]any

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

    paths := routes["paths"].(map[string]any)

    for k, v := range paths {
        result := map[string]any{}

        paths2 := v.(map[string]any)
        for kk, vv := range paths2 {
            url := k
            method := strings.ToUpper(kk)

            data := vv.(map[string]any)
            title := data["summary"].(string)

            slug := array.ArrGetWithGoch(data, "x-lakego.slug").ToString()
            if slug == "" {
                slug = hash.MD5(datebin.NowDatetimeString() + random.String(15))
            }

            // 排序
            sort := array.ArrGetWithGoch(data, "x-lakego.sort", "100").ToString()

            err := model.NewAuthRule().
                Where("url = ?", url).
                Where("method = ?", method).
                First(&result).
                Error
            if err != nil || len(result) < 1 {
                tags := array.ArrGetWithGoch(data, "tags").ToStringSlice()

                tag := ""
                if len(tags) > 0 {
                    tag = tags[0]
                }

                parentid := "0"
                if tag != "" {
                    result2 := map[string]any{}
                    err = model.NewAuthRule().
                        Where("title = ?", tag).
                        Where("method = ?", "OPTIONS").
                        First(&result2).
                        Error
                    if err != nil || len(result2) < 1 {
                        insertDataP := model.AuthRule{
                            Parentid: "0",
                            Title: tag,
                            Url: "#",
                            Method: "OPTIONS",
                            Slug: "#",
                            Description: "",
                            Listorder: "100",
                            Status: 1,
                            AddTime: int(datebin.NowTime()),
                            AddIp: "127.0.0.1",
                        }

                        errP := model.NewDB().Create(&insertDataP).Error
                        if errP == nil {
                            parentid = insertDataP.ID
                        }

                    } else {
                        parentid = result2["id"].(string)
                    }
                }

                insertData := model.AuthRule{
                    Parentid: parentid,
                    Title: title,
                    Url: url,
                    Method: method,
                    Slug: slug,
                    Description: "",
                    Listorder: sort,
                    Status: 1,
                    AddTime: int(datebin.NowTime()),
                    AddIp: "127.0.0.1",
                }

                model.NewDB().Create(&insertData)
            } else {
                model.NewAuthRule().
                    Where("url = ?", url).
                    Where("method = ?", method).
                    Updates(map[string]any{
                        "title": title,
                        "slug": slug,
                        "listorder": sort,
                    })
            }

        }

    }

    fmt.Println("权限路由导入成功")
}

