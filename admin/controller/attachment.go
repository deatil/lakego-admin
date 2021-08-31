package controller

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/admin/model"
)

/**
 * 附件
 *
 * @create 2021-8-31
 * @author deatil
 */
type Attachment struct {
    Base
}

/**
 * 列表
 */
func (control *Attachment) Index(ctx *gin.Context) {
    start := ctx.Query("start")
    limit := ctx.Query("limit")

    order := ctx.DefaultQuery("order", "ASC")

    searchword := ctx.DefaultQuery("searchword", "")

    startTime := control.FormatDate(ctx.DefaultQuery("start_time", ""))
    endTime := control.FormatDate(ctx.DefaultQuery("end_time", ""))

    status := control.SwitchStatus(ctx.DefaultQuery("status", ""))

    total := 0

    list := []string{}

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": list,
    })
}

/**
 * 详情
 */
func (control *Attachment) Detail(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 启用
 */
func (control *Attachment) Enable(ctx *gin.Context) {

    // 数据输出
    control.Success(ctx, "文件启用成功")
}

/**
 * 禁用
 */
func (control *Attachment) Disable(ctx *gin.Context) {

    // 数据输出
    control.Success(ctx, "文件禁用成功")
}

/**
 * 删除
 */
func (control *Attachment) Delete(ctx *gin.Context) {

    // 数据输出
    control.Success(ctx, "文件删除成功")
}

/**
 * 下载码
 */
func (control *Attachment) DownloadCode(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 下载
 */
func (control *Attachment) Download(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

