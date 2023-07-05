package controller

import (
    "github.com/deatil/go-goch/goch"
    "github.com/deatil/lakego-doak/lakego/router"

    admin_controller "github.com/deatil/lakego-doak-admin/admin/controller"

    "github.com/deatil/lakego-doak-extension/extension/model"
    "github.com/deatil/lakego-doak-extension/extension/service"
)

/**
 * 扩展
 *
 * @create 2023-4-20
 * @author deatil
 */
type Extension struct {
    admin_controller.Base
}

// 扩展列表
// @Summary 扩展列表
// @Description 扩展列表
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param searchword query string false "搜索关键字"
// @Param order      query string false "排序，示例：id__DESC"
// @Param status     query string false "状态"
// @Param start      query string false "开始数据量"
// @Param limit      query string false "每页数量"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.index"}
func (this *Extension) Index(ctx *router.Context) {
    // 模型
    extModel := model.NewExtension()

    // 排序
    order := ctx.DefaultQuery("order", "add_time__DESC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "add_time") {
        orders[0] = "add_time"
    }

    extModel = extModel.Order(orders[0] + " " + orders[1])

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        extModel = extModel.Where("add_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        extModel = extModel.Where("add_time <= ?", this.FormatDate(endTime))
    }

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        extModel = extModel.Where(
            model.NewDB().
                Where("name LIKE ?", searchword).
                Where("title LIKE ?", searchword).
                Or("info LIKE ?", searchword),
        )
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        extModel = extModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    extModel = extModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]any, 0)

    // 列表
    extModel.Find(&list)

    var total int64

    // 总数
    err := extModel.
        Offset(-1).
        Limit(-1).
        Count(&total).
        Error
    if err != nil {
        this.Error(ctx, "获取失败")
        return
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": list,
    })
}

// 本地扩展
// @Summary 本地扩展
// @Description 本地扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/local [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.local"}
func (this *Extension) Local(ctx *router.Context) {
    exts := service.NewExtension().Local()
    total := len(exts)

    this.SuccessWithData(ctx, "获取成功", router.H{
        "total": total,
        "list": exts,
    })
}

// 安装扩展
// @Summary 安装扩展
// @Description 安装扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/{name}/install [post]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.install"}
func (this *Extension) Inatll(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    err := service.NewExtensionWithCtx(ctx).Inatll(name)
    if err != nil {
        this.Error(ctx, err.Error())
        return
    }

    this.Success(ctx, "安装扩展成功")
}

// 卸载扩展
// @Summary 卸载扩展
// @Description 卸载扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/{name}/uninstall [delete]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.uninstall"}
func (this *Extension) Uninstall(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    err := service.NewExtension().Uninstall(name)
    if err != nil {
        this.Error(ctx, err.Error())
        return
    }

    this.Success(ctx, "卸载扩展成功")
}

// 更新扩展
// @Summary 更新扩展
// @Description 更新扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/{name}/upgrade [put]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.upgrade"}
func (this *Extension) Upgrade(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    err := service.NewExtensionWithCtx(ctx).Upgrade(name)
    if err != nil {
        this.Error(ctx, err.Error())
        return
    }

    this.Success(ctx, "更新扩展成功")
}

// 扩展排序
// @Summary 扩展排序
// @Description 扩展排序
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name      query string true "扩展名称"
// @Param listorder formData string true "排序值"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/{name}/sort [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.sort"}
func (this *Extension) Listorder(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 排序
    listorder := 100
    if post["listorder"] != "" {
        listorder = goch.ToInt(post["listorder"])
    }

    err := service.NewExtension().Listorder(name, listorder)
    if err != nil {
        this.Error(ctx, err.Error())
        return
    }

    this.Success(ctx, "更新排序成功")
}

// 启用扩展
// @Summary 启用扩展
// @Description 启用扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/{name}/enable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.enable"}
func (this *Extension) Enable(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    err := service.NewExtension().Enable(name)
    if err != nil {
        this.Error(ctx, err.Error())
        return
    }

    this.Success(ctx, "启用扩展成功")
}

// 禁用扩展
// @Summary 禁用扩展
// @Description 禁用扩展
// @Tags 扩展
// @Accept  application/json
// @Produce application/json
// @Param name query string true "扩展名称"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /extension/{name}/disable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.extension.disable"}
func (this *Extension) Disable(ctx *router.Context) {
    name := ctx.Param("name")
    if name == "" {
        this.Error(ctx, "扩展不能为空")
        return
    }

    err := service.NewExtension().Disable(name)
    if err != nil {
        this.Error(ctx, err.Error())
        return
    }

    this.Success(ctx, "禁用扩展成功")
}
