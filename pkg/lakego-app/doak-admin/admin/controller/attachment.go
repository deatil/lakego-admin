package controller

import (
    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/random"
    "github.com/deatil/lakego-doak/lakego/facade/storage"
    "github.com/deatil/lakego-doak/lakego/facade/cache"

    "github.com/deatil/lakego-doak-admin/admin/model"
    "github.com/deatil/lakego-doak-admin/admin/support/url"
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

// 附件列表
// @Summary 附件列表
// @Description 附件列表
// @Tags 附件
// @Accept  application/json
// @Produce application/json
// @Param order      query string false "排序，示例：id__DESC"
// @Param searchword query string false "搜索关键字"
// @Param start_time query string false "开始时间"
// @Param end_time   query string false "结束时间"
// @Param status     query string false "状态"
// @Param start      query string false "开始数据量"
// @Param limit      query string false "每页数量"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /attachment [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.index","sort":"151"}
func (this *Attachment) Index(ctx *router.Context) {
    // 附件模型
    attachModel := model.NewAttachment()

    // 排序
    order := ctx.DefaultQuery("order", "add_time__DESC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "name" &&
        orders[0] != "update_time" &&
        orders[0] != "add_time") {
        orders[0] = "add_time"
    }

    attachModel = attachModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        attachModel = attachModel.Where(
            model.NewDB().
                Where("name LIKE ?", searchword).
                Or("extension LIKE ?", searchword).
                Or("disk LIKE ?", searchword),
        )
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        attachModel = attachModel.Where("create_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        attachModel = attachModel.Where("create_time <= ?", this.FormatDate(endTime))
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        attachModel = attachModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    attachModel = attachModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]any, 0)

    // 列表
    attachModel = attachModel.Find(&list)

    var total int64

    // 总数
    err := attachModel.Offset(-1).Limit(-1).Count(&total).Error
    if err != nil {
        this.Error(ctx, "获取失败")
        return
    }

    newList := make([]map[string]any, 0)
    for _, v := range list {
        v["url"] = url.AttachmentUrl(v["path"].(string), v["disk"].(string))
        newList = append(newList, v)
    }

    // 数据输出
    this.SuccessWithData(ctx, "获取成功", router.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": newList,
    })
}

// 附件详情
// @Summary 附件详情
// @Description 附件详情
// @Tags 附件
// @Accept  application/json
// @Produce application/json
// @Param id path string true "附件ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /attachment/{id} [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.detail","sort":"152"}
func (this *Attachment) Detail(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "文件ID不能为空")
        return
    }

    newId := goch.ToString(id)

    result := map[string]any{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", newId).
        First(&result).
        Error
    if err != nil {
        this.Error(ctx, "文件信息不存在")
        return
    }

    // 格式化链接
    result["url"] = url.AttachmentUrl(result["path"].(string), result["disk"].(string))

    // 数据输出
    this.SuccessWithData(ctx, "获取成功", result)
}

// 附件删除
// @Summary 附件删除
// @Description 附件删除
// @Tags 附件
// @Accept  application/json
// @Produce application/json
// @Param id path string true "附件ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /attachment/{id} [delete]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.delete","sort":"153"}
func (this *Attachment) Delete(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]any{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "文件信息不存在")
        return
    }

    // 附件模型
    err2 := model.NewAttachment().
        Delete(&model.Attachment{
            ID: id,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "文件删除失败")
        return
    }

    // 删除具体文件
    storage.NewWithDisk(result["disk"].(string)).
        Delete(result["path"].(string))

    // 数据输出
    this.Success(ctx, "文件删除成功")
}

// 附件启用
// @Summary 附件启用
// @Description 附件启用
// @Tags 附件
// @Accept  application/json
// @Produce application/json
// @Param id path string true "附件ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /attachment/{id}/enable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.enable","sort":"154"}
func (this *Attachment) Enable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]any{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "文件信息不存在")
        return
    }

    if result["status"].(int) == 1 {
        this.Error(ctx, "文件已启用")
        return
    }

    err2 := model.NewAttachment().
        Where("id = ?", id).
        Updates(map[string]any{
            "status": 1,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "文件启用失败")
        return
    }

    // 数据输出
    this.Success(ctx, "文件启用成功")
}

// 附件禁用
// @Summary 附件禁用
// @Description 附件禁用
// @Tags 附件
// @Accept  application/json
// @Produce application/json
// @Param id path string true "附件ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /attachment/{id}/disable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.disable","sort":"155"}
func (this *Attachment) Disable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]any{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "文件信息不存在")
        return
    }

    if result["status"].(int) == 0 {
        this.Error(ctx, "文件已禁用")
        return
    }

    err2 := model.NewAttachment().
        Where("id = ?", id).
        Updates(map[string]any{
            "status": 0,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "文件禁用失败")
        return
    }

    // 数据输出
    this.Success(ctx, "文件禁用成功")
}

// 附件下载码
// @Summary 附件下载码
// @Description 附件下载码
// @Tags 附件
// @Accept  application/json
// @Produce application/json
// @Param id path string true "附件ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /attachment/downcode/{id} [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.downcode","sort":"156"}
func (this *Attachment) DownloadCode(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]any{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "文件信息不存在")
        return
    }

    // 添加到缓存
    code := hash.MD5(goch.ToString(datebin.NowTime()) + random.String(10))
    cache.New().Put(code, result["id"].(string), 300)

    // 数据输出
    this.SuccessWithData(ctx, "获取成功", router.H{
        "code": code,
    })
}

// 附件下载
// @Summary 附件下载
// @Description 附件下载
// @Tags 附件
// @Accept  application/json
// @Produce application/force-download
// @Param code path string true "附件下载码"
// @Success 200 {string} string ""
// @Router /attachment/download/{code} [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.attachment.download","sort":"157"}
func (this *Attachment) Download(ctx *router.Context) {
    code := ctx.Param("code")
    if code == "" {
        this.ReturnString(ctx, "下载ID不能为空")
        return
    }

    fileId, _ := cache.New().Pull(code)
    if fileId == "" {
        this.ReturnString(ctx, "文件ID错误")
        return
    }

    result := map[string]any{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", fileId).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.ReturnString(ctx, "文件数据不存在")
        return
    }

    // 文件路径
    filePath := url.AttachmentPath(result["path"].(string), result["disk"].(string))

    if filePath == "" {
        this.ReturnString(ctx, "文件不存在")
        return
    }

    fs := filesystem.New()
    if !fs.Exists(filePath) {
        this.ReturnString(ctx, "文件不存在")
        return
    }

    // 下载
    this.DownloadFile(ctx, filePath, result["name"].(string))
}

