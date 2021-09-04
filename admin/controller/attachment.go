package controller

import (
    "strings"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/support/time"
    "lakego-admin/lakego/support/cast"
    "lakego-admin/lakego/support/random"
    "lakego-admin/lakego/facade/storage"
    "lakego-admin/lakego/facade/cache"

    "lakego-admin/admin/model"
    "lakego-admin/admin/support/url"
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
    // 附件模型
    attachModel := model.NewAttachment()

    // 排序
    order := ctx.DefaultQuery("order", "id__DESC")
    orders := strings.SplitN(order, "__", 2)
    attachModel = attachModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        attachModel = attachModel.
            Or("name LIKE ?", searchword).
            Or("extension LIKE ?", searchword).
            Or("driver LIKE ?", searchword)
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        attachModel = attachModel.Where("create_time >= ?", control.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        attachModel = attachModel.Where("create_time <= ?", control.FormatDate(endTime))
    }

    status := control.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        attachModel = attachModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := cast.ToInt(start)
    newLimit := cast.ToInt(limit)

    attachModel = attachModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]interface{}, 0)

    // 列表
    attachModel = attachModel.Find(&list)

    var total int64

    // 总数
    err := attachModel.Offset(-1).Limit(-1).Count(&total).Error
    if err != nil {
        control.Error(ctx, "获取失败")
        return
    }

    newList := make([]map[string]interface{}, 0)
    for _, v := range list {
        v["url"] = url.AttachmentUrl(v["path"].(string), v["disk"].(string))
        newList = append(newList, v)
    }

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": newList,
    })
}

/**
 * 详情
 */
func (control *Attachment) Detail(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "文件ID不能为空")
        return
    }

    newId := cast.ToString(id)

    result := map[string]interface{}{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", newId).
        First(&result).
        Error
    if err != nil {
        control.Error(ctx, "文件信息不存在")
        return
    }

    // 格式化链接
    result["url"] = url.AttachmentUrl(result["path"].(string), result["disk"].(string))

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", result)
}

/**
 * 启用
 */
func (control *Attachment) Enable(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]interface{}{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "文件信息不存在")
        return
    }

    if result["status"].(int) == 1 {
        control.Error(ctx, "文件已启用")
        return
    }

    err2 := model.NewAttachment().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "status": 1,
        }).
        Error
    if err2 != nil {
        control.Error(ctx, "文件启用失败")
        return
    }

    // 数据输出
    control.Success(ctx, "文件启用成功")
}

/**
 * 禁用
 */
func (control *Attachment) Disable(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]interface{}{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "文件信息不存在")
        return
    }

    if result["status"].(int) == 0 {
        control.Error(ctx, "文件已禁用")
        return
    }

    err2 := model.NewAttachment().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "status": 0,
        }).
        Error
    if err2 != nil {
        control.Error(ctx, "文件禁用失败")
        return
    }

    // 数据输出
    control.Success(ctx, "文件禁用成功")
}

/**
 * 删除
 */
func (control *Attachment) Delete(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]interface{}{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "文件信息不存在")
        return
    }

    // 附件模型
    err2 := model.NewAttachment().
        Delete(&model.Attachment{
            ID: id,
        }).
        Error
    if err2 != nil {
        control.Error(ctx, "文件删除失败")
        return
    }

    // 删除具体文件
    storage.NewWithDisk(result["disk"].(string)).
        Delete(result["path"].(string))

    // 数据输出
    control.Success(ctx, "文件删除成功")
}

/**
 * 下载码
 */
func (control *Attachment) DownloadCode(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "文件ID不能为空")
        return
    }

    result := map[string]interface{}{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "文件信息不存在")
        return
    }

    // 添加到缓存
    code := hash.MD5(cast.ToString(time.NowTime()) + random.String(10))
    cache.New().Put(code, result["id"].(string), 300)

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{
        "code": code,
    })
}

/**
 * 下载
 */
func (control *Attachment) Download(ctx *gin.Context) {
    code := ctx.Param("code")
    if code == "" {
        control.ReturnString(ctx, "code值不能为空")
        return
    }

    fileId, _ := cache.New().Pull(code)
    if fileId == "" {
        control.ReturnString(ctx, "文件信息不存在")
        return
    }

    result := map[string]interface{}{}

    // 附件模型
    err := model.NewAttachment().
        Where("id = ?", fileId).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.ReturnString(ctx, "文件信息不存在")
        return
    }

    // 文件路径
    filePath := url.AttachmentPath(result["path"].(string), result["disk"].(string))

    // 下载
    control.DownloadFile(ctx, filePath, result["name"].(string))
}

