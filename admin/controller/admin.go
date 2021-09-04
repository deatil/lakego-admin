package controller

import (
    "strings"
    "encoding/json"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/collection"
    "lakego-admin/lakego/support/cast"

    "lakego-admin/admin/model"
)

/**
 * 管理员
 *
 * @create 2021-9-2
 * @author deatil
 */
type Admin struct {
    Base
}

/**
 * 列表
 */
func (control *Admin) Index(ctx *gin.Context) {
    // 模型
    adminModel := model.NewAdmin()

    // 排序
    order := ctx.DefaultQuery("order", "id__DESC")
    orders := strings.SplitN(order, "__", 2)
    if orders[0] != "id" ||
        orders[0] != "name" ||
        orders[0] != "last_active" ||
        orders[0] != "add_time" {
        orders[0] = "id"
    }

    adminModel = adminModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        adminModel = adminModel.
            Or("name LIKE ?", searchword).
            Or("nickname LIKE ?", searchword).
            Or("email LIKE ?", searchword)
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        adminModel = adminModel.Where("add_time >= ?", control.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        adminModel = adminModel.Where("add_time <= ?", control.FormatDate(endTime))
    }

    status := control.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        adminModel = adminModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := cast.ToInt(start)
    newLimit := cast.ToInt(limit)

    adminModel = adminModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]interface{}, 0)

    // 列表
    adminModel = adminModel.
        Select([]string{
            "id", "name", "nickname",
            "email", "avatar",
            "is_root", "status",
            "last_active", "last_ip",
            "update_time", "update_ip",
            "add_time", "add_ip",
        }).
        Find(&list)

    var total int64

    // 总数
    err := adminModel.
        Offset(-1).
        Limit(-1).
        Count(&total).
        Error
    if err != nil {
        control.Error(ctx, "获取失败")
        return
    }

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
func (control *Admin) Detail(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "账号ID不能为空")
        return
    }

    newId := cast.ToString(id)

    var info = model.Admin{}

    // 附件模型
    err := model.NewAdmin().
        Where("id = ?", newId).
        Preload("Groups").
        First(&info).
        Error
    if err != nil {
        control.Error(ctx, "账号不存在")
        return
    }

    // 结构体转map
    data, _ := json.Marshal(&info)
    adminData := map[string]interface{}{}
    json.Unmarshal(data, &adminData)

    newInfoGroups:= collection.Collect(adminData["Groups"]).
        Select("id", "parentid", "title", "description").
        ToMapArray()

    newInfo := map[string]interface{}{
        "id": adminData["id"],
        "name": adminData["name"],
        "nickname": adminData["nickname"],
        "email": adminData["email"],
        "avatar": model.AttachmentUrl(adminData["avatar"].(string)),
        "is_root": adminData["is_root"],
        "status": adminData["status"],
        "last_active": adminData["last_active"],
        "last_ip": adminData["last_ip"],
        "update_time": adminData["update_time"],
        "update_ip": adminData["update_ip"],
        "add_time": adminData["add_time"],
        "add_ip": adminData["add_ip"],
        "groups": newInfoGroups,
    }

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", newInfo)
}

/**
 * 管理员权限
 */
func (control *Admin) Rules(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 删除
 */
func (control *Admin) Delete(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 添加
 */
func (control *Admin) Create(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 更新
 */
func (control *Admin) Update(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 修改头像
 */
func (control *Admin) UpdateAvatar(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 修改密码
 */
func (control *Admin) UpdatePasssword(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 授权
 */
func (control *Admin) Access(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 启用
 */
func (control *Admin) Enable(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 禁用
 */
func (control *Admin) Disable(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 退出
 */
func (control *Admin) Logout(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

