package controller

import (
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
)

/**
 * 后台首页
 *
 * @create 2025-5-12
 * @author deatil
 */
type Index struct {
    controller.Base
}

// 后台首页
// @Summary 首页信息
// @Description 首页信息
// @Tags ext-demo
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /demo [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.ext.demo-index"}
func (this *Index) Index(ctx *gin.Context) {
    this.Success(ctx, "demo index")
}

// 详情
// @Summary 详情
// @Description 信息详情
// @Tags ext-demo
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /demo/:id [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.ext.demo-detail"}
func (this *Index) Detail(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    this.Success(ctx, "demo [" + id + "] detail")
}

// 删除
// @Summary 删除
// @Description 信息删除
// @Tags ext-demo
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /demo/:id [delete]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.ext.demo-delete"}
func (this *Index) Delete(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    this.Success(ctx, "demo delete [" + id + "] success")
}

