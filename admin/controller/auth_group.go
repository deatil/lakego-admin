package controller

import (
    "strings"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/tree"
    "lakego-admin/lakego/helper"
    "lakego-admin/lakego/collection"
    "lakego-admin/lakego/support/cast"
    "lakego-admin/lakego/support/time"

    "lakego-admin/admin/model"
    authGroupValidate "lakego-admin/admin/validate/authgroup"
    authGroupRepository "lakego-admin/admin/repository/authgroup"
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

/**
 * 列表
 */
func (control *AuthGroup) Index(ctx *gin.Context) {
    // 模型
    groupModel := model.NewAuthGroup()

    // 排序
    order := ctx.DefaultQuery("order", "id__DESC")
    orders := strings.SplitN(order, "__", 2)
    if orders[0] != "id" ||
        orders[0] != "title" ||
        orders[0] != "add_time" {
        orders[0] = "id"
    }

    groupModel = groupModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        groupModel = groupModel.
            Or("title LIKE ?", searchword)
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        groupModel = groupModel.Where("add_time >= ?", control.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        groupModel = groupModel.Where("add_time <= ?", control.FormatDate(endTime))
    }

    status := control.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        groupModel = groupModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := cast.ToInt(start)
    newLimit := cast.ToInt(limit)

    groupModel = groupModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]interface{}, 0)

    // 列表
    groupModel = groupModel.Find(&list)

    var total int64

    // 总数
    err := groupModel.
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
 * 树结构
 */
func (control *AuthGroup) IndexTree(ctx *gin.Context) {
    list := make([]map[string]interface{}, 0)

    err := model.NewAuthGroup().
        Order("listorder ASC").
        Order("add_time ASC").
        Find(&list).
        Error
    if err != nil {
        control.Error(ctx, "获取失败")
        return
    }

    newTree := tree.New()
    list2 := newTree.WithData(list).Build("0", "", 1)

    control.SuccessWithData(ctx, "获取成功", gin.H{
        "list": list2,
    })
}

/**
 * 子列表
 */
func (control *AuthGroup) IndexChildren(ctx *gin.Context) {
    id := ctx.Query("id")
    if id == "" {
        control.Error(ctx, "ID错误")
        return
    }

    var data interface{}

    typ := ctx.Query("type")
    if typ == "list" {
        data = authGroupRepository.GetChildren(id)
    } else {
        data = authGroupRepository.GetChildrenIds(id)
    }

    control.SuccessWithData(ctx, "获取成功", gin.H{
        "list": data,
    })
}

/**
 * 详情
 */
func (control *AuthGroup) Detail(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
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
        control.Error(ctx, "信息不存在")
        return
    }

    // 结构体转map
    groupData := model.FormatStructToMap(&info)

    ruleAccesses := make([]string, 0)
    if len(groupData["RuleAccesses"].([]interface{})) > 0 {
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

    control.SuccessWithData(ctx, "获取成功", groupData)
}

/**
 * 删除
 */
func (control *AuthGroup) Delete(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
        return
    }

    // 详情
    var info model.AuthGroup
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&info).
        Error
    if err != nil {
        control.Error(ctx, "信息不存在")
        return
    }

    // 子级
    var childInfo model.AuthGroup
    err2 := model.NewAuthGroup().
        Where("parentid = ?", id).
        First(&childInfo).
        Error
    if err2 != nil {
        control.Error(ctx, "请删除子分组后再操作")
        return
    }

    // 删除
    err3 := model.NewAuthGroup().
        Delete(&model.AuthGroup{
            ID: id,
        }).
        Error
    if err3 != nil {
        control.Error(ctx, "信息删除失败")
        return
    }

    control.Success(ctx, "信息删除成功")
}

/**
 * 添加
 */
func (control *AuthGroup) Create(ctx *gin.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    validateErr := authGroupValidate.Create(post)
    if validateErr != "" {
        control.Error(ctx, validateErr)
        return
    }

    listorder := cast.ToString(post["listorder"])
    status := cast.ToInt(post["status"])

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
        AddTime: time.NowTimeToInt(),
        AddIp: helper.GetRequestIp(ctx),
    }

    err2 := model.NewDB().
        Create(&insertData).
        Error
    if err2 != nil {
        control.Error(ctx, "信息添加失败")
        return
    }

    control.SuccessWithData(ctx, "信息添加成功", gin.H{
        "id": insertData.ID,
    })
}

/**
 * 更新
 */
func (control *AuthGroup) Update(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    validateErr := authGroupValidate.Update(post)
    if validateErr != "" {
        control.Error(ctx, validateErr)
        return
    }

    listorder := cast.ToInt(post["listorder"])
    status := cast.ToInt(post["status"])

    if status == 1 {
        status = 1
    } else {
        status = 0
    }

    err3 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "parentid": post["parentid"].(string),
            "title": post["title"].(string),
            "description": post["description"].(string),
            "listorder": listorder,
            "status": status,
            "add_time": time.NowTimeToInt(),
            "add_ip": helper.GetRequestIp(ctx),
        }).
        Error
    if err3 != nil {
        control.Error(ctx, "信息修改失败")
        return
    }

    control.Success(ctx, "信息修改成功")
}

/**
 * 排序
 */
func (control *AuthGroup) Listorder(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 排序
    listorder := 0
    if post["listorder"] != "" {
        listorder = cast.ToInt(post["listorder"])
    } else {
        listorder = 100
    }

    err2 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "listorder": listorder,
        }).
        Error
    if err2 != nil {
        control.Error(ctx, "更新排序失败")
        return
    }

    control.Success(ctx, "更新排序成功")
}

/**
 * 启用
 */
func (control *AuthGroup) Enable(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    if result["status"] == 1 {
        control.Error(ctx, "信息已启用")
        return
    }

    err2 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "status": 1,
        }).
        Error
    if err2 != nil {
        control.Error(ctx, "启用失败")
        return
    }

    control.Success(ctx, "启用成功")
}

/**
 * 禁用
 */
func (control *AuthGroup) Disable(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    if result["status"] == 0 {
        control.Error(ctx, "信息已禁用")
        return
    }

    err2 := model.NewAuthGroup().
        Where("id = ?", id).
        Updates(map[string]interface{}{
            "status": 0,
        }).
        Error
    if err2 != nil {
        control.Error(ctx, "禁用失败")
        return
    }

    control.Success(ctx, "禁用成功")
}

/**
 * 授权
 */
func (control *AuthGroup) Access(ctx *gin.Context) {
    id := ctx.Param("id")
    if id == "" {
        control.Error(ctx, "ID不能为空")
        return
    }

    // 查询
    result := map[string]interface{}{}
    err := model.NewAuthGroup().
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        control.Error(ctx, "信息不存在")
        return
    }

    // 模型
    err2 := model.NewAuthRuleAccess().
        Where("group_id = ?", id).
        Delete(&model.AuthRuleAccess{}).
        Error
    if err2 != nil {
        control.Error(ctx, "授权失败")
        return
    }

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

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
            insertData = append(insertData, model.AuthRuleAccess{
                GroupId: id,
                RuleId: value,
            })
        }

        model.NewDB().Create(&insertData)
    }

    control.Success(ctx, "授权成功")
}

