package controller

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
)

/**
 * 默认模块
 *
 * @create 2022-11-21
 * @author deatil
 */
type Index struct {
    controller.Base
}

// admin 模块首页
// @Summary admin 模块首页
// @Description admin 模块首页
// @Tags 管理后台
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router / [get]
// @x-lakego {"slug": "lakego-admin.admin.index"}
func (this *Index) Index(ctx *gin.Context) {
    data := "admin index data"

    this.SuccessWithData(ctx, "获取成功", gin.H{
        "data": data,
    })
}

