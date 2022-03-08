package controller

import (
    "strings"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/support/cast"
    "github.com/deatil/lakego-doak/lakego/support/time"

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
// @Param order query string false "排序，示例：id__DESC"
// @Param searchword query string false "搜索关键字"
// @Param start_time query string false "开始时间"
// @Param end_time query string false "结束时间"
// @Param status query string false "状态"
// @Param start query string false "开始数据量"
// @Param limit query string false "每页数量"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /action-log [get]
// @Security Bearer
func (this *ActionLog) Index(ctx *router.Context) {
    // 模型
    logModel := model.NewActionLog()

    // 排序
    order := ctx.DefaultQuery("order", "id__DESC")
    orders := strings.SplitN(order, "__", 2)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "add_time") {
        orders[0] = "id"
    }

    if orders[1] == "" || (orders[1] != "DESC" && orders[1] != "ASC") {
        orders[1] = "DESC"
    }

    logModel = logModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        logModel = logModel.
            Or("name LIKE ?", searchword).
            Or("url LIKE ?", searchword)
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        logModel = logModel.Where("add_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        logModel = logModel.Where("add_time <= ?", this.FormatDate(endTime))
    }

    // 请求方式
    method := ctx.DefaultQuery("method", "")
    if method != "" {
        logModel = logModel.Where("method = ?", method)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := cast.ToInt(start)
    newLimit := cast.ToInt(limit)

    logModel = logModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]interface{}, 0)

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
func (this *ActionLog) Clear(ctx *router.Context) {
    // 清除
    err := model.NewActionLog().
        Where("add_time <= ?", int(time.BeforeDayTime(30))).
        Delete(&model.ActionLog{}).
        Error
    if err != nil {
        this.Error(ctx, "30天前日志清除失败")
        return
    }

    this.Success(ctx, "30天前日志清除成功")
}
