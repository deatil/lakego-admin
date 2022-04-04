package controller

import (
    "strings"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/tree"
    "github.com/deatil/lakego-doak/lakego/router"

    "github.com/deatil/lakego-doak-admin/admin/model"
    authRuleValidate "github.com/deatil/lakego-doak-admin/admin/validate/authrule"
    authRuleRepository "github.com/deatil/lakego-doak-admin/admin/repository/authrule"
)

/**
 * 权限菜单
 *
 * @create 2021-9-12
 * @author deatil
 */
type AuthRule struct {
    Base
}

// 权限菜单列表
// @Summary 权限菜单列表
// @Description 权限菜单列表
// @Tags 权限菜单
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
// @Router /auth/rule [get]
// @Security Bearer
func (this *AuthRule) Index(ctx *router.Context) {
    // 模型
    ruleModel := model.NewAuthRule()

    // 排序
    order := ctx.DefaultQuery("order", "add_time__DESC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "title" &&
        orders[0] != "url" &&
        orders[0] != "method" &&
        orders[0] != "add_time") {
        orders[0] = "add_time"
    }

    ruleModel = ruleModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        ruleModel = ruleModel.
            Where("title LIKE ?", searchword)
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        ruleModel = ruleModel.Where("add_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        ruleModel = ruleModel.Where("add_time <= ?", this.FormatDate(endTime))
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        ruleModel = ruleModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    ruleModel = ruleModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]interface{}, 0)

    // 列表
    ruleModel = ruleModel.Find(&list)

    var total int64

    // 总数
    err := ruleModel.
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

// 权限菜单树结构
// @Summary 权限菜单树结构
// @Description 权限菜单树结构
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /auth/rule/tree [get]
// @Security Bearer
func (this *AuthRule) IndexTree(ctx *router.Context) {
    list := make([]map[string]interface{}, 0)

    err := model.NewAuthRule().
        Order("listorder ASC").
        Order("add_time ASC").
        Find(&list).
        Error
    if err != nil {
        this.Error(ctx, "获取失败")
        return
    }

    newTree := tree.New()
    list2 := newTree.WithData(list).Build("0", "", 1)

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": list2,
    })
}

// 权限菜单子列表
// @Summary 权限菜单子列表
// @Description 权限菜单子列表
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id query string true "权限菜单ID"
// @Param type query string false "数据类型，可选值：list | ids"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /auth/rule/children [get]
// @Security Bearer
func (this *AuthRule) IndexChildren(ctx *router.Context) {
    id := ctx.Query("id")
    if id == "" {
        this.Error(ctx, "ID错误")
        return
    }

    var data interface{}

    typ := ctx.Query("type")
    if typ == "list" {
        data = authRuleRepository.GetChildren(id)
    } else {
        data = authRuleRepository.GetChildrenIds(id)
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": data,
    })
}

// 权限菜单详情
// @Summary 权限菜单详情
// @Description 权限菜单详情
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id path string true "权限菜单ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /auth/rule/{id} [get]
// @Security Bearer
func (this *AuthRule) Detail(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    var info model.AuthRule

    // 模型
    err := model.NewAuthRule().
        Where("id = ?", id).
        First(&info).
        Error
    if err != nil {
        this.Error(ctx, "信息不存在")
        return
    }

    // 结构体转map
    ruleData := model.FormatStructToMap(&info)

    this.SuccessWithData(ctx, "获取成功", ruleData)
}

// 权限菜单删除
// @Summary 权限菜单删除
// @Description 权限菜单删除
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id path string true "权限菜单ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "信息删除成功", "data": ""}"
// @Router /auth/rule/{id} [delete]
// @Security Bearer
func (this *AuthRule) Delete(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 详情
    var info model.AuthRule
    err := model.NewAuthRule().
        Where("id = ?", id).
        First(&info).
        Error
    if err != nil {
        this.Error(ctx, "信息不存在")
        return
    }

    // 子级
    var total int64
    err2 := model.NewAuthRule().
        Where("parentid = ?", id).
        Count(&total).
        Error
    if err2 != nil || total > 0 {
        this.Error(ctx, "请删除子权限后再操作")
        return
    }

    // 删除
    err3 := model.NewAuthRule().
        Delete(&model.AuthRule{
            ID: id,
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "信息删除失败")
        return
    }

    this.Success(ctx, "信息删除成功")
}

// 清空特定ID权限
// @Summary 清空特定ID权限
// @Description 清空特定ID权限
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param ids formData string true "权限ID列表"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "删除特定权限成功", "data": ""}"
// @Router /auth/rule/clear [delete]
// @Security Bearer
func (this *AuthRule) Clear(ctx *router.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    if post["ids"] == "" {
        this.Error(ctx, "权限ID列表不能为空")
        return
    }
    ids := post["ids"].(string)

    newIds := strings.Split(ids, ",")
    for _, id := range newIds {
        // 详情
        var info model.AuthRule
        err := model.NewAuthRule().
            Where("id = ?", id).
            First(&info).
            Error
        if err != nil {
            continue
        }

        // 子级
        var total int64
        err2 := model.NewAuthRule().
            Where("parentid = ?", id).
            Count(&total).
            Error
        if err2 != nil || total > 0 {
            continue
        }

        // 删除
        err3 := model.NewAuthRule().
            Delete(&model.AuthRule{
                ID: id,
            }).
            Error
        if err3 != nil {
            continue
        }

    }

    this.Success(ctx, "删除特定权限成功")
}

// 权限菜单添加
// @Summary 权限菜单添加
// @Description 权限菜单添加
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param parentid formData string true "父级ID"
// @Param title formData string true "名称"
// @Param url formData string true "URL链接"
// @Param method formData string true "请求方式"
// @Param slug formData string true "别名 Slug"
// @Param description formData string true "描述"
// @Param listorder formData string true "排序"
// @Param status formData string true "状态"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "信息添加成功", "data": ""}"
// @Router /auth/rule [post]
// @Security Bearer
func (this *AuthRule) Create(ctx *router.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    validateErr := authRuleValidate.Create(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    listorder := 0
    if post["listorder"] != "" {
        listorder = goch.ToInt(post["listorder"])
    } else {
        listorder = 100
    }

    status := 0
    if post["status"].(float64) == 1 {
        status = 1
    }

    insertData := model.AuthRule{
        Parentid: post["parentid"].(string),
        Title: post["title"].(string),
        Url: post["url"].(string),
        Method: strings.ToUpper(post["method"].(string)),
        Slug: post["slug"].(string),
        Description: post["description"].(string),
        Listorder: goch.ToString(listorder),
        Status: status,
        AddTime: int(datebin.NowTime()),
        AddIp: router.GetRequestIp(ctx),
    }

    err2 := model.NewDB().
        Create(&insertData).
        Error
    if err2 != nil {
        this.Error(ctx, "信息添加失败")
        return
    }

    this.SuccessWithData(ctx, "信息添加成功", router.H{
        "id": insertData.ID,
    })
}

// 权限菜单更新
// @Summary 权限菜单更新
// @Description 权限菜单更新
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id path string true "权限菜单ID"
// @Param parentid formData string true "父级ID"
// @Param title formData string true "名称"
// @Param url formData string true "URL链接"
// @Param method formData string true "请求方式"
// @Param slug formData string true "别名 Slug"
// @Param description formData string true "描述"
// @Param listorder formData string true "排序"
// @Param status formData string true "状态"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "信息修改成功", "data": ""}"
// @Router /auth/rule/{id} [put]
// @Security Bearer
func (this *AuthRule) Update(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthRule().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    validateErr := authRuleValidate.Update(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    listorder := 0
    if post["listorder"] != "" {
        listorder = goch.ToInt(post["listorder"])
    } else {
        listorder = 100
    }

    status := 0
    if post["status"].(float64) == 1 {
        status = 1
    }

    err3 := model.NewAuthRule().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "parentid": post["parentid"].(string),
            "title": post["title"].(string),
            "url": post["url"].(string),
            "method": post["method"].(string),
            "slug": post["slug"].(string),
            "description": post["description"].(string),
            "listorder": listorder,
            "status": status,
            "add_time": int(datebin.NowTime()),
            "add_ip": router.GetRequestIp(ctx),
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "信息修改失败")
        return
    }

    this.Success(ctx, "信息修改成功")
}

// 权限菜单排序
// @Summary 权限菜单排序
// @Description 权限菜单排序
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id path string true "权限菜单ID"
// @Param listorder formData string true "排序值"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "更新排序成功", "data": ""}"
// @Router /auth/rule/{id}/sort [patch]
// @Security Bearer
func (this *AuthRule) Listorder(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthRule().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 排序
    listorder := 0
    if post["listorder"] != "" {
        listorder = goch.ToInt(post["listorder"])
    } else {
        listorder = 100
    }

    err2 := model.NewAuthRule().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "listorder": listorder,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "更新排序失败")
        return
    }

    this.Success(ctx, "更新排序成功")
}

// 权限菜单启用
// @Summary 权限菜单启用
// @Description 权限菜单启用
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id path string true "权限菜单ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "启用成功", "data": ""}"
// @Router /auth/rule/{id}/enable [patch]
// @Security Bearer
func (this *AuthRule) Enable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthRule().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    if result["status"] == 1 {
        this.Error(ctx, "信息已启用")
        return
    }

    err2 := model.NewAuthRule().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "status": 1,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "启用失败")
        return
    }

    this.Success(ctx, "启用成功")
}

// 权限菜单禁用
// @Summary 权限菜单禁用
// @Description 权限菜单禁用
// @Tags 权限菜单
// @Accept application/json
// @Produce application/json
// @Param id path string true "权限菜单ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "禁用成功", "data": ""}"
// @Router /auth/rule/{id}/disable [patch]
// @Security Bearer
func (this *AuthRule) Disable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthRule().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    if result["status"] == 0 {
        this.Error(ctx, "信息已禁用")
        return
    }

    err2 := model.NewAuthRule().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "status": 0,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "禁用失败")
        return
    }

    this.Success(ctx, "禁用成功")
}
