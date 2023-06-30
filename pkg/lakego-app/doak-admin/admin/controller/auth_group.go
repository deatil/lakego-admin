package controller

import (
    "strings"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-tree/tree"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/collection"

    "github.com/deatil/lakego-doak-admin/admin/model"
    authGroupValidate "github.com/deatil/lakego-doak-admin/admin/validate/authgroup"
    authGroupRepository "github.com/deatil/lakego-doak-admin/admin/repository/authgroup"
)

/**
 * 权限分组
 *
 * @create 2021-9-12
 * @author deatil
 */
type AuthGroup struct {
    Base
}

// 权限分组列表
// @Summary 权限分组列表
// @Description 权限分组列表
// @Tags 权限分组
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
// @Router /auth/group [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.index"}
func (this *AuthGroup) Index(ctx *router.Context) {
    // 模型
    groupModel := model.NewAuthGroup()

    // 排序
    order := ctx.DefaultQuery("order", "add_time__DESC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "title" &&
        orders[0] != "listorder" &&
        orders[0] != "add_time") {
        orders[0] = "add_time"
    }

    groupModel = groupModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        groupModel = groupModel.
            Where("title LIKE ?", searchword)
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        groupModel = groupModel.Where("add_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        groupModel = groupModel.Where("add_time <= ?", this.FormatDate(endTime))
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        groupModel = groupModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    groupModel = groupModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]any, 0)

    // 列表
    groupModel.Find(&list)

    var total int64

    // 总数
    err := groupModel.
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

// 权限分组树结构
// @Summary 权限分组树结构
// @Description 权限分组树结构
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/tree [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.tree"}
func (this *AuthGroup) IndexTree(ctx *router.Context) {
    list := make([]map[string]any, 0)

    err := model.NewAuthGroup().
        Order("listorder ASC").
        Order("add_time ASC").
        Find(&list).
        Error
    if err != nil {
        this.Error(ctx, "获取失败")
        return
    }

    newList := tree.New[string]().
        WithData(list).
        Build("0", "", 1)

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": newList,
    })
}

// 权限分组子列表
// @Summary 权限分组子列表
// @Description 权限分组子列表
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id   query string true  "权限分组ID"
// @Param type query string false "数据类型，可选值：list | ids"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/children [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.children"}
func (this *AuthGroup) IndexChildren(ctx *router.Context) {
    id := ctx.Query("id")
    if id == "" {
        this.Error(ctx, "ID错误")
        return
    }

    var data any

    typ := ctx.Query("type")
    if typ == "list" {
        data = authGroupRepository.GetChildren(id)
    } else {
        data = authGroupRepository.GetChildrenIds(id)
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": data,
    })
}

// 权限分组详情
// @Summary 权限分组详情
// @Description 权限分组详情
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id path string true "权限分组ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id} [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.detail"}
func (this *AuthGroup) Detail(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    var info model.AuthGroup

    // 模型
    err := model.NewAuthGroup().
        Where("id = ?", id).
        Preload("RuleAccesses").
        First(&info).
        Error
    if err != nil {
        this.Error(ctx, "信息不存在")
        return
    }

    // 结构体转map
    groupData := model.FormatStructToMap(&info)

    ruleAccesses := make([]string, 0)
    if len(groupData["RuleAccesses"].([]any)) > 0 {
        ruleAccesses = collection.
            Collect(groupData["RuleAccesses"]).
            Pluck("rule_id").
            ToStringArray()
    }

    delete(groupData, "RuleAccesses")
    groupData["rule_accesses"] = ruleAccesses

    // 格式化
    groupData = collection.
        Collect(groupData).
        Only([]string{
            "id",
            "parentid",
            "title",
            "description",
            "listorder",
            "status",
            "update_time",
            "update_ip",
            "add_time",
            "add_ip",
            "rule_accesses",
        }).
        ToMap()

    this.SuccessWithData(ctx, "获取成功", groupData)
}

// 权限分组添加
// @Summary 权限分组添加
// @Description 权限分组添加
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param parentid    formData string true "父级ID"
// @Param title       formData string true "名称"
// @Param description formData string false "描述"
// @Param listorder   formData string true "排序"
// @Param status      formData string true "状态"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group [post]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.create"}
func (this *AuthGroup) Create(ctx *router.Context) {
    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    validateErr := authGroupValidate.Create(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    listorder := goch.ToInt(post["listorder"])
    status := goch.ToInt(post["status"])

    if status == 1 {
        status = 1
    } else {
        status = 0
    }

    insertData := model.AuthGroup{
        Parentid: post["parentid"].(string),
        Title: post["title"].(string),
        Description: post["description"].(string),
        Listorder: listorder,
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

// 权限分组更新
// @Summary 权限分组更新
// @Description 权限分组更新
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id          path     string true "权限分组ID"
// @Param parentid    formData string true "父级ID"
// @Param title       formData string true "名称"
// @Param description formData string false "描述"
// @Param listorder   formData string true "排序"
// @Param status      formData string true "状态"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id} [put]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.update"}
func (this *AuthGroup) Update(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    validateErr := authGroupValidate.Update(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    listorder := goch.ToInt(post["listorder"])
    status := goch.ToInt(post["status"])

    if status == 1 {
        status = 1
    } else {
        status = 0
    }

    err3 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]any{
            "parentid": post["parentid"].(string),
            "title": post["title"].(string),
            "description": post["description"].(string),
            "listorder": listorder,
            "status": status,
            "update_time": int(datebin.NowTime()),
            "update_ip": router.GetRequestIp(ctx),
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "信息修改失败")
        return
    }

    this.Success(ctx, "信息修改成功")
}

// 权限分组删除
// @Summary 权限分组删除
// @Description 权限分组删除
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id path string true "权限分组ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id} [delete]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.delete"}
func (this *AuthGroup) Delete(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 详情
    var info model.AuthGroup
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&info).
        Error
    if err != nil {
        this.Error(ctx, "信息不存在")
        return
    }

    // 子级
    var total int64
    err2 := model.NewAuthGroup().
        Where("parentid = ?", id).
        Count(&total).
        Error
    if err2 != nil || total > 0 {
        this.Error(ctx, "请删除子分组后再操作")
        return
    }

    // 删除
    err3 := model.NewAuthGroup().
        Delete(&model.AuthGroup{
            ID: id,
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "信息删除失败")
        return
    }

    this.Success(ctx, "信息删除成功")
}

// 权限分组排序
// @Summary 权限分组排序
// @Description 权限分组排序
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id        path     string true "权限分组ID"
// @Param listorder formData string true "排序值"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id}/sort [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.sort"}
func (this *AuthGroup) Listorder(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 排序
    listorder := 0
    if post["listorder"] != "" {
        listorder = goch.ToInt(post["listorder"])
    } else {
        listorder = 100
    }

    err2 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]any{
            "listorder": listorder,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "更新排序失败")
        return
    }

    this.Success(ctx, "更新排序成功")
}

// 权限分组启用
// @Summary 权限分组启用
// @Description 权限分组启用
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id path string true "权限分组ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id}/enable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.enable"}
func (this *AuthGroup) Enable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    if result["status"] == 1 {
        this.Error(ctx, "信息已启用")
        return
    }

    err2 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]any{
            "status": 1,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "启用失败")
        return
    }

    this.Success(ctx, "启用成功")
}

// 权限分组禁用
// @Summary 权限分组禁用
// @Description 权限分组禁用
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id path string true "权限分组ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id}/disable [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.disable"}
func (this *AuthGroup) Disable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    if result["status"] == 0 {
        this.Error(ctx, "信息已禁用")
        return
    }

    err2 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]any{
            "status": 0,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "禁用失败")
        return
    }

    this.Success(ctx, "禁用成功")
}

// 权限分组授权
// @Summary 权限分组授权
// @Description 权限分组授权
// @Tags 权限分组
// @Accept  application/json
// @Produce application/json
// @Param id     path     string true "权限分组ID"
// @Param access formData string true "权限列表，半角逗号分隔"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /auth/group/{id}/access [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.auth-group.access"}
func (this *AuthGroup) Access(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "信息不存在")
        return
    }

    // 模型
    err2 := model.NewAuthRuleAccess().
        Where("group_id = ?", id).
        Delete(&model.AuthRuleAccess{}).
        Error
    if err2 != nil {
        this.Error(ctx, "授权失败")
        return
    }

    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 添加权限
    access := post["access"].(string)
    if access != "" {
        accessIds := strings.Split(access, ",")

        newAccessIds := collection.
            Collect(accessIds).
            Unique().
            ToStringArray()

        insertData := make([]model.AuthRuleAccess, 0)
        for _, value := range newAccessIds {
            if value == "" {
                continue
            }

            insertData = append(insertData, model.AuthRuleAccess{
                GroupId: id,
                RuleId: value,
            })
        }

        model.NewDB().Create(&insertData)
    }

    this.Success(ctx, "授权成功")
}

