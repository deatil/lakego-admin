package controller

import (
    "strings"

    "github.com/deatil/lakego-doak/lakego/tree"
    "github.com/deatil/lakego-doak/lakego/tool"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/support/cast"
    "github.com/deatil/lakego-doak/lakego/support/time"

    "github.com/deatil/lakego-doak-admin/admin/model"
    authRuleValidate "github.com/deatil/lakego-doak-admin/admin/validate/authrule"
    authRuleRepository "github.com/deatil/lakego-doak-admin/admin/repository/authrule"
)

/**
 * 菜单权限
 *
 * @create 2021-9-12
 * @author deatil
 */
type AuthRule struct {
    Base
}

/**
 * 列表
 */
func (this *AuthRule) Index(ctx *router.Context) {
    // 模型
    ruleModel := model.NewAuthRule()

    // 排序
    order := ctx.DefaultQuery("order", "id__DESC")
    orders := strings.SplitN(order, "__", 2)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "title" &&
        orders[0] != "url" &&
        orders[0] != "method" &&
        orders[0] != "add_time") {
        orders[0] = "id"
    }

    if orders[1] == "" || (orders[1] != "DESC" && orders[1] != "ASC") {
        orders[1] = "DESC"
    }

    ruleModel = ruleModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        ruleModel = ruleModel.
            Or("title LIKE ?", searchword)
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

    newStart := cast.ToInt(start)
    newLimit := cast.ToInt(limit)

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

/**
 * 树结构
 */
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

/**
 * 子列表
 */
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

/**
 * 详情
 */
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

/**
 * 删除
 */
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

/**
 * 清空特定ID权限
 */
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

/**
 * 添加
 */
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
        listorder = cast.ToInt(post["listorder"])
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
        Listorder: cast.ToString(listorder),
        Status: status,
        AddTime: time.NowTimeToInt(),
        AddIp: tool.GetRequestIp(ctx),
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

/**
 * 更新
 */
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
        listorder = cast.ToInt(post["listorder"])
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
            "add_time": time.NowTimeToInt(),
            "add_ip": tool.GetRequestIp(ctx),
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "信息修改失败")
        return
    }

    this.Success(ctx, "信息修改成功")
}

/**
 * 排序
 */
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
        listorder = cast.ToInt(post["listorder"])
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

/**
 * 启用
 */
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

/**
 * 禁用
 */
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
