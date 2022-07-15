package controller

import (
    "github.com/deatil/lakego-doak/lakego/router"

    adminController "github.com/deatil/lakego-doak-admin/admin/controller"

    "github.com/deatil/lakego-doak-database/database/service"
)

/**
 * 数据库管理
 *
 * @create 2022-5-28
 * @author deatil
 */
type Database struct {
    adminController.Base
}

// 数据库列表
// @Summary 数据库列表
// @Description 数据库列表
// @Tags 数据库管理
// @Accept  application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /database [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.database.index"}
func (this *Database) Index(ctx *router.Context) {
    list := service.NewDatabase().GetTableStatus()

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": list,
    })
}

// 数据库表详情
// @Summary 数据库表详情
// @Description 数据库表详情
// @Tags 数据库管理
// @Accept  application/json
// @Produce application/json
// @Param name path string true "数据表名"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /database/{name} [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.database.detail"}
func (this *Database) Detail(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "数据表名不能为空")
        return
    }

    list := service.NewDatabase().GetFullColumnsFromTable(name)

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": list,
    })
}

// 优化数据表
// @Summary 优化数据表
// @Description 优化数据表
// @Tags 数据库管理
// @Accept  application/json
// @Produce application/json
// @Param name path string true "数据表名"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /database/{name}/optimize [post]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.database.optimize"}
func (this *Database) Optimize(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "数据表名不能为空")
        return
    }

    status := service.NewDatabase().OptimizeTable(name)
    if !status {
        this.Error(ctx, "优化数据表失败")
        return
    }

    this.Success(ctx, "优化数据表成功")
}

// 修复数据表
// @Summary 修复数据表
// @Description 修复数据表
// @Tags 数据库管理
// @Accept  application/json
// @Produce application/json
// @Param name path string true "数据表名"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /database/{name}/repair [post]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.database.repair"}
func (this *Database) Repair(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "数据表名不能为空")
        return
    }

    status := service.NewDatabase().RepairTable(name)
    if !status {
        this.Error(ctx, "修复数据表失败")
        return
    }

    this.Success(ctx, "修复数据表成功")
}
