package controller

import (
    "os"
    "runtime"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/support/time"

    "github.com/deatil/lakego-doak/admin/auth/admin"
)

/**
 * 系统
 *
 * @create 2021-9-13
 * @author deatil
 */
type System struct {
    Base
}

/**
 * 系统信息
 */
func (this *System) Info(ctx *router.Context) {
    hostname, _ := os.Hostname()
    // netInfo, _ := net.Interfaces()

    // 系统信息
    conf := config.New("version")

    name := conf.GetString("Name")
    nameMini := conf.GetString("NameMini")
    // logo := conf.GetString("Logo")
    release := conf.GetString("Release")
    version := conf.GetString("Version")

    // 服务器时间
    nowDatetime := time.TimeStampToDate(time.NowTimeToInt())

    data := router.H{
        "goos": runtime.GOOS,
        "goarch": runtime.GOARCH,
        // "goroot": runtime.GOROOT(),
        "version": runtime.Version(),
        "numcpu": runtime.NumCPU(),
        "hostname": hostname,

        "system": router.H{
            "name": name,
            "nameMini": nameMini,
            // "logo": logo,
            "release": release,
            "version": version,
        },

        "datetime": nowDatetime,
    }

    this.SuccessWithData(ctx, "获取成功", data)
}

/**
 * 权限 slug 列表
 */
func (this *System) Rules(ctx *router.Context) {
    adminInfo, _ := ctx.Get("admin")
    rules := adminInfo.(*admin.Admin).GetRuleSlugs()

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": rules,
    })
}
