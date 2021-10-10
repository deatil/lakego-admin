package controller

import (
    "strings"
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/support/cast"
    "github.com/deatil/lakego-admin/lakego/support/time"

    "lakego-admin/admin/model"
)

/**
 * 操作日志
 *
 * @create 2021-9-28
 * @author deatil
 */
type ActionLog struct {
    Base
}

/**
 * 列表
 */
func (control *ActionLog) Index(ctx *gin.Context) {
    // 模型
    logModel := model.NewActionLog()

    // 排序
    order := ctx.DefaultQuery("order", "id__DESC")
    orders := strings.SplitN(order, "__", 2)
    if orders[0] != "id" ||
        orders[0] != "add_time" {
        orders[0] = "id"
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
        logModel = logModel.Where("add_time >= ?", control.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        logModel = logModel.Where("add_time <= ?", control.FormatDate(endTime))
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
        control.Error(ctx, "获取失败")
        return
    }

    control.SuccessWithData(ctx, "获取成功", gin.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": list,
    })
}

/**
 * 清除 30 天前的数据
 */
func (control *ActionLog) Clear(ctx *gin.Context) {
    // 清除
    err := model.NewActionLog().
        Where("add_time <= ?", time.BeforeTimeToInt(-30)).
        Delete(&model.ActionLog{}).
        Error
    if err != nil {
        control.Error(ctx, "30天前日志清除失败")
        return
    }

    control.Success(ctx, "30天前日志清除成功")
}
