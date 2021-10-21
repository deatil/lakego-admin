package controller

import (
    "os"
    "runtime"

    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/admin/auth/admin"
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
func (this *System) Info(ctx *gin.Context) {
    hostname, _ := os.Hostname()
    // netInfo, _ := net.Interfaces()

    data := gin.H{
        "goos": runtime.GOOS,
        "goarch": runtime.GOARCH,
        "goroot": runtime.GOROOT(),
        "version": runtime.Version(),
        "numcpu": runtime.NumCPU(),
        "hostname": hostname,
    }

    this.SuccessWithData(ctx, "获取成功", data)
}

/**
 * 权限 slug 列表
 */
func (this *System) Rules(ctx *gin.Context) {
    adminInfo, _ := ctx.Get("admin")
    rules := adminInfo.(*admin.Admin).GetRuleSlugs()

    this.SuccessWithData(ctx, "获取成功", gin.H{
        "list": rules,
    })
}