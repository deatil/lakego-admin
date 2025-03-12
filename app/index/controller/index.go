package controller

import (
    "runtime"
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak/lakego/facade"
    // "github.com/deatil/lakego-doak/lakego/router"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
)

/**
 * 默认模块
 *
 * @create 2022-9-3
 * @author deatil
 */
type Index struct {
    controller.Base
}

// 默认模块首页信息
// @Summary 默认模块首页
// @Description 默认模块首页信息
// @Tags 默认模块
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router / [get]
// @x-lakego {"slug": "lakego-admin.index.index"}
func (this *Index) Index(ctx *gin.Context) {
    conf := facade.Config("version")

    name := conf.GetString("name")
    nameMini := conf.GetString("name-mini")
    release := conf.GetString("release")
    version := conf.GetString("version")

    goVersion := runtime.Version()

    this.SuccessWithData(ctx, "获取成功", gin.H{
        "name": name,
        "nameMini": nameMini,
        "release": release,
        "version": version,

        "goVersion": goVersion,
    })
}

