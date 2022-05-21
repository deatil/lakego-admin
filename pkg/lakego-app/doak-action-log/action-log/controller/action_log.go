package controller

import (
    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/router"

    adminController "github.com/deatil/lakego-doak-admin/admin/controller"

    "github.com/deatil/lakego-doak-action-log/action-log/model"
)

/**
 * 操作日志
 *
 * @create 2021-9-28
 * @author deatil
 */
type ActionLog struct {
    adminController.Base
}

// 操作日志列表
// @Summary 操作日志列表
// @Description 操作日志列表
// @Tags 操作日志
// @Accept application/json
// @Produce application/json
// @Param searchword query string false "搜索关键字"
// @Param order query string false "排序，示例：id__DESC"
// @Param start_time query string false "开始时间"
// @Param end_time query string false "结束时间"
// @Param method query string false "请求方法"
// @Param status query string false "状态"
// @Param start query string false "开始数据量"
// @Param limit query string false "每页数量"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /action-log [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.action-log.index"}
func (this *ActionLog) Index(ctx *router.Context) {
    // 模型
    logModel := model.NewActionLog()

    // 排序
    order := ctx.DefaultQuery("order", "time__DESC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "time") {
        orders[0] = "time"
    }

    logModel = logModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        logModel = logModel.Where(
            model.NewDB().
                Where("name LIKE ?", searchword).
                Or("url LIKE ?", searchword),
        )
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        logModel = logModel.Where("time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        logModel = logModel.Where("time <= ?", this.FormatDate(endTime))
    }

    // 请求方式
    method := ctx.DefaultQuery("method", "")
    if method != "" {
        logModel = logModel.Where("method = ?", method)
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        logModel = logModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    logModel = logModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]any, 0)

    // 列表
    logModel = logModel.Find(&list)

    var total int64

    // 总数
    err := logModel.
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

// 清除 30 天前的数据
// @Summary 清除 30 天前的日志数据
// @Description 清除 30 天前的日志数据
// @Tags 操作日志
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "30天前日志清除成功", "data": ""}"
// @Router /action-log/clear [delete]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.action-log.clear"}
func (this *ActionLog) Clear(ctx *router.Context) {
    // 清除
    err := model.NewActionLog().
        Where("time <= ?", int(datebin.Now().SubDays(30).Timestamp())).
        Delete(&model.ActionLog{}).
        Error
    if err != nil {
        this.Error(ctx, "30天前日志清除失败")
        return
    }

    this.Success(ctx, "30天前日志清除成功")
}
