package controller

import (
    "strings"
    "encoding/json"

    "github.com/deatil/go-goch/goch"
    "github.com/deatil/go-hash/hash"
    "github.com/deatil/go-tree/tree"
    "github.com/deatil/go-datebin/datebin"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/collection"
    "github.com/deatil/lakego-doak/lakego/facade/auth"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/cache"
    "github.com/deatil/lakego-doak/lakego/facade/permission"

    "github.com/deatil/lakego-doak-admin/admin/model"
    "github.com/deatil/lakego-doak-admin/admin/model/scope"
    "github.com/deatil/lakego-doak-admin/admin/auth/admin"
    "github.com/deatil/lakego-doak-admin/admin/support/jwt"
    authPassword "github.com/deatil/lakego-doak/lakego/auth/password"
    adminValidate "github.com/deatil/lakego-doak-admin/admin/validate/admin"
    adminRepository "github.com/deatil/lakego-doak-admin/admin/repository/admin"
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

// 账号列表
// @Summary 账号列表
// @Description 管理员账号列表
// @Tags 管理员
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
// @Router /admin [get]
// @Security Bearer
func (this *Admin) Index(ctx *router.Context) {
    // 模型
    adminModel := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx))

    // 排序
    order := ctx.DefaultQuery("order", "add_time__ASC")
    orders := this.FormatOrderBy(order)
    if orders[0] == "" ||
        (orders[0] != "id" &&
        orders[0] != "name" &&
        orders[0] != "last_active" &&
        orders[0] != "add_time") {
        orders[0] = "add_time"
    }

    adminModel = adminModel.Order(orders[0] + " " + orders[1])

    // 搜索条件
    searchword := ctx.DefaultQuery("searchword", "")
    if searchword != "" {
        searchword = "%" + searchword + "%"

        adminModel = adminModel.Where(
            model.NewDB().
                Where("name LIKE ?", searchword).
                Or("nickname LIKE ?", searchword).
                Or("email LIKE ?", searchword),
        )
    }

    // 时间条件
    startTime := ctx.DefaultQuery("start_time", "")
    if startTime != "" {
        adminModel = adminModel.Where("add_time >= ?", this.FormatDate(startTime))
    }

    endTime := ctx.DefaultQuery("end_time", "")
    if endTime != "" {
        adminModel = adminModel.Where("add_time <= ?", this.FormatDate(endTime))
    }

    status := this.SwitchStatus(ctx.DefaultQuery("status", ""))
    if status != -1 {
        adminModel = adminModel.Where("status = ?", status)
    }

    // 分页相关
    start := ctx.DefaultQuery("start", "0")
    limit := ctx.DefaultQuery("limit", "10")

    newStart := goch.ToInt(start)
    newLimit := goch.ToInt(limit)

    adminModel = adminModel.
        Offset(newStart).
        Limit(newLimit)

    list := make([]map[string]any, 0)

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
        this.Error(ctx, "获取失败")
        return
    }

    newlist := make([]map[string]any, 0)
    for _, item := range list {
        item["avatar_url"] = model.AttachmentUrl(item["avatar"].(string))
        newlist = append(newlist, item)
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "start": start,
        "limit": limit,
        "total": total,
        "list": newlist,
    })
}

// 账号详情
// @Summary 账号详情
// @Description 管理员账号详情
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /admin/{id} [get]
// @Security Bearer
func (this *Admin) Detail(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    var info = model.Admin{}

    // 模型
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Preload("Groups").
        First(&info).
        Error
    if err != nil {
        this.Error(ctx, "账号不存在")
        return
    }

    // 结构体转map
    data, _ := json.Marshal(&info)
    adminData := map[string]any{}
    json.Unmarshal(data, &adminData)

    newInfoGroups := make([]map[string]any, 0)
    if len(adminData["Groups"].([]any)) > 0 {
        newInfoGroups = collection.Collect(adminData["Groups"].([]any)).
            Select("id", "parentid", "title", "description").
            ToMapArray()
    }

    avatar := model.AttachmentUrl(adminData["avatar"].(string))

    newInfo := collection.Collect(adminData).
        Only([]string{
            "id", "name", "nickname", "email",
            "introduce", "is_root", "status",
            "last_active", "last_ip",
            "update_time", "update_ip",
            "add_time", "add_ip",
        }).
        ToMap()

    newInfo["groups"] = newInfoGroups
    newInfo["avatar"] = avatar

    this.SuccessWithData(ctx, "获取成功", newInfo)
}

// 账号权限
// @Summary 账号权限
// @Description 账号权限
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /admin/{id}/rules [get]
// @Security Bearer
func (this *Admin) Rules(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    var info = model.Admin{}

    // 模型
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Preload("Groups").
        First(&info).
        Error
    if err != nil {
        this.Error(ctx, "账号不存在")
        return
    }

    // 结构体转map
    data, _ := json.Marshal(&info)
    adminData := map[string]any{}
    json.Unmarshal(data, &adminData)

    groupids := collection.Collect(adminData["Groups"]).
        Pluck("id").
        ToStringArray()

    rules := adminRepository.GetRules(groupids)

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": rules,
    })
}

// 添加账号所需分组
// @Summary 添加账号所需分组
// @Description 添加账号所需分组
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /admin/groups [get]
// @Security Bearer
func (this *Admin) Groups(ctx *router.Context) {
    adminInfo, _ := ctx.Get("admin")
    adminData := adminInfo.(*admin.Admin)

    list := make([]map[string]any, 0)
    if adminData.IsSuperAdministrator() {
        err := model.NewAuthGroup().
            Order("listorder ASC").
            Order("add_time ASC").
            Select([]string{
                "id",
                "parentid",
                "title",
                "description",
            }).
            Find(&list).
            Error
        if err != nil {
            this.Error(ctx, "获取失败")
            return
        }

        list = collection.
            Collect(list).
            Each(func(item, value any) (any, bool) {
                value2 := value.(map[string]any)
                group := map[string]any{
                    "id": value2["id"],
                    "parentid": goch.ToString(value2["parentid"]),
                    "title": value2["title"],
                    "description": value2["description"],
                };

                return group, true
            }).
            ToMapArray()

        newTree := tree.New()
        list2 := newTree.WithData(list).Build("0", "", 1)

        list = newTree.BuildFormatList(list2, "0")
    } else {
        list = adminData.GetGroupChildren()
    }

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": list,
    })
}

// 添加账号
// @Summary 添加账号
// @Description 添加账号
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param name formData string true "名称"
// @Param email formData string true "邮箱"
// @Param nickname formData string true "昵称"
// @Param introduce formData string true "描述"
// @Param status formData string true "状态"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /admin [post]
// @Security Bearer
func (this *Admin) Create(ctx *router.Context) {
    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    validateErr := adminValidate.Create(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    status := 0
    if post["status"].(float64) == 1 {
        status = 1
    }

    // 模型
    result := map[string]any{}
    err := model.NewAdmin().
        Where("name = ?", post["name"].(string)).
        Or("email = ?", post["email"].(string)).
        First(&result).
        Error
    if !(err != nil || len(result) < 1) {
        this.Error(ctx, "邮箱或者账号已经存在")
        return
    }

    insertData := model.Admin{
        Name: post["name"].(string),
        Nickname: post["nickname"].(string),
        Email: post["email"].(string),
        Introduce: post["introduce"].(string),
        Status: status,
        AddTime: int(datebin.NowTime()),
        AddIp: router.GetRequestIp(ctx),
    }

    err2 := model.NewDB().
        Create(&insertData).
        Error
    if err2 != nil {
        this.Error(ctx, "添加账号失败")
        return
    }

    model.NewDB().Create(&model.AuthGroupAccess{
        AdminId: insertData.ID,
        GroupId: post["group_id"].(string),
    })

    this.SuccessWithData(ctx, "添加账号成功", router.H{
        "id": insertData.ID,
    })
}

// 更新账号
// @Summary 更新账号
// @Description 管理员更新信息
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Param name formData string true "名称"
// @Param email formData string true "邮箱"
// @Param nickname formData string true "昵称"
// @Param introduce formData string true "描述"
// @Param status formData string true "状态"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /admin/{id} [put]
// @Security Bearer
func (this *Admin) Update(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能修改自己的账号")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    validateErr := adminValidate.Update(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    status := 0
    if post["status"].(float64) == 1 {
        status = 1
    }

    // 链接db
    db := model.NewDB()

    // 验证
    result2 := map[string]any{}
    err2 := model.NewAdmin().
        Where(db.Where("id != ?", id).Where("name = ?", post["name"].(string))).
        Or(db.Where("id != ?", id).Where("email = ?", post["email"].(string))).
        First(&result2).
        Error
    if !(err2 != nil || len(result2) < 1) {
        this.Error(ctx, "管理员账号或者邮箱已经存在")
        return
    }

    err3 := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Updates(map[string]any{
            "name": post["name"].(string),
            "nickname": post["nickname"].(string),
            "email": post["email"].(string),
            "introduce": post["introduce"].(string),
            "status": status,
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "账号修改失败")
        return
    }

    this.Success(ctx, "账号修改成功")
}

// 删除账号
// @Summary 删除账号
// @Description 管理员账号删除
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "获取成功", "data": ""}"
// @Router /admin/{id} [delete]
// @Security Bearer
func (this *Admin) Delete(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能删除自己的账号")
        return
    }

    result := map[string]any{}

    // 模型
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    authAdminId := config.New("auth").GetString("auth.admin-id")
    if authAdminId == id {
        this.Error(ctx, "当前账号不能被删除")
        return
    }

    // 删除
    err2 := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Delete(&model.Admin{
            ID: id,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "账号删除失败")
        return
    }

    this.Success(ctx, "账号删除成功")
}

// 修改账号头像
// @Summary 修改账号头像
// @Description 修改管理员账号头像
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Param avatar formData string true "头像数据ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/{id}/avatar [patch]
// @Security Bearer
func (this *Admin) UpdateAvatar(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能修改自己的账号")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    validateErr := adminValidate.UpdateAvatar(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    err3 := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Updates(map[string]any{
            "avatar": post["avatar"].(string),
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "修改头像失败")
        return
    }

    this.Success(ctx, "修改头像成功")
}

// 修改账号密码
// @Summary 修改账号密码
// @Description 修改管理员账号密码
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Param password formData string true "新密码"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/{id}/password [patch]
// @Security Bearer
func (this *Admin) UpdatePasssword(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能修改自己的账号")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    password := post["password"].(string)
    if len(password) != 32 {
        this.Error(ctx, "密码格式错误")
        return
    }

    // 生成密码
    pass, encrypt := authPassword.MakePassword(password)

    err3 := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Updates(map[string]any{
            "password": pass,
            "password_salt": encrypt,
        }).
        Error
    if err3 != nil {
        this.Error(ctx, "密码修改失败")
        return
    }

    this.Success(ctx, "密码修改成功")
}

// 账号启用
// @Summary 账号启用
// @Description 管理员账号启用
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/{id}/enable [patch]
// @Security Bearer
func (this *Admin) Enable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能修改自己的账号")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    if result["status"] == 1 {
        this.Error(ctx, "账号已启用")
        return
    }

    err2 := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Updates(map[string]any{
            "status": 1,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "启用账号失败")
        return
    }

    this.Success(ctx, "启用账号成功")
}

// 账号禁用
// @Summary 账号禁用
// @Description 管理员账号禁用
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "管理员ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/{id}/disable [patch]
// @Security Bearer
func (this *Admin) Disable(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能修改自己的账号")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    if result["status"] == 0 {
        this.Error(ctx, "账号已禁用")
        return
    }

    err2 := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        Updates(map[string]any{
            "status": 0,
        }).
        Error
    if err2 != nil {
        this.Error(ctx, "禁用账号失败")
        return
    }

    this.Success(ctx, "禁用账号成功")
}

// 账号退出
// @Summary 账号退出
// @Description 管理员账号退出
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param refreshToken path string true "刷新 token"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/logout/{refreshToken} [delete]
// @Security Bearer
func (this *Admin) Logout(ctx *router.Context) {
    refreshToken := ctx.Param("refreshToken")
    if refreshToken == "" {
        this.Error(ctx, "refreshToken不能为空")
        return
    }

    c := cache.New()

    if c.Has(hash.MD5(refreshToken)) {
        this.Error(ctx, "refreshToken已失效")
        return
    }

    // jwt
    aud := jwt.GetJwtAud(ctx)
    jwter := auth.NewWithAud(aud)

    // 拿取数据
    claims, claimsErr := jwter.GetRefreshTokenClaims(refreshToken)
    if claimsErr != nil {
        this.Error(ctx, "refreshToken 已失效")
        return
    }

    // 当前账号ID
    refreshAdminid := jwter.GetDataFromTokenClaims(claims, "id")

    // 过期时间
    exp := jwter.GetFromTokenClaims(claims, "exp")
    iat := jwter.GetFromTokenClaims(claims, "iat")
    refreshTokenExpiresIn := exp.(float64) - iat.(float64)

    nowAdminId, _ := ctx.Get("admin_id")
    if refreshAdminid == nowAdminId.(string) {
        this.Error(ctx, "你不能退出你的账号")
        return
    }

    c.Put(hash.MD5(refreshToken), "no", int64(refreshTokenExpiresIn))

    model.NewAdmin().
        Where("id = ?", refreshAdminid).
        Updates(map[string]any{
            "refresh_time": int(datebin.NowTime()),
            "refresh_ip": router.GetRequestIp(ctx),
        })

    this.Success(ctx, "账号退出成功")
}

// 账号授权
// @Summary 账号授权
// @Description 管理员账号授权
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Param id path string true "刷新 token"
// @Param access formData string true "权限列表，半角逗号分隔"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/{id}/access [patch]
// @Security Bearer
func (this *Admin) Access(ctx *router.Context) {
    id := ctx.Param("id")
    if id == "" {
        this.Error(ctx, "账号ID不能为空")
        return
    }

    adminId, _ := ctx.Get("admin_id")
    if id == adminId.(string) {
        this.Error(ctx, "你不能修改自己的账号")
        return
    }

    // 查询
    result := map[string]any{}
    err := model.NewAdmin().
        Scopes(scope.AdminWithAccess(ctx)).
        Where("id = ?", id).
        First(&result).
        Error
    if err != nil || len(result) < 1 {
        this.Error(ctx, "账号信息不存在")
        return
    }

    // 模型
    err2 := model.NewAuthGroupAccess().
        Where("admin_id = ?", id).
        Delete(&model.AuthGroupAccess{}).
        Error
    if err2 != nil {
        this.Error(ctx, "账号授权分组失败")
        return
    }

    // 接收数据
    post := make(map[string]any)
    ctx.BindJSON(&post)

    access := post["access"].(string)
    if access != "" {
        adminInfo, _ := ctx.Get("admin")
        adminData := adminInfo.(*admin.Admin)

        groupIds := adminData.GetGroupChildrenIds()
        accessIds := strings.Split(access, ",")

        newAccessIds := collection.
            Collect(accessIds).
            Unique().
            ToStringArray()

        intersectAccess := make([]string, 0)
        if !adminData.IsSuperAdministrator() {
            intersectAccess = collection.
                Collect(groupIds).
                Intersect(accessIds).
                ToStringArray()
        } else {
            intersectAccess = newAccessIds
        }

        insertData := make([]model.AuthGroupAccess, 0)
        for _, value := range intersectAccess {
            insertData = append(insertData, model.AuthGroupAccess{
                AdminId: id,
                GroupId: value,
            })
        }

        model.NewDB().Create(&insertData)
    }

    this.Success(ctx, "账号授权分组成功")
}

// 账号权限同步
// @Summary 账号权限同步
// @Description 管理员账号权限同步
// @Tags 管理员
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "...", "data": ""}"
// @Router /admin/reset-permission [put]
// @Security Bearer
func (this *Admin) ResetPermission(ctx *router.Context) {
    // 清空原始数据
    model.ClearRulesData()

    // 权限
    ruleList := make([]model.AuthRuleAccess, 0)
    err := model.NewAuthRuleAccess().
        Preload("Rule", "status = ?", 1).
        Find(&ruleList).
        Error
    if err != nil {
        this.Error(ctx, "权限同步失败")
        return
    }

    ruleListMap := model.FormatStructToArrayMap(ruleList)

    // 分组
    groupList := make([]model.AuthGroupAccess, 0)
    err2 := model.NewAuthGroupAccess().
        Preload("Group", "status = ?", 1).
        Find(&groupList).
        Error
    if err2 != nil {
        this.Error(ctx, "权限同步失败")
        return
    }

    groupListMap := model.FormatStructToArrayMap(groupList)

    // permission
    cas := permission.New()

    // 添加权限
    if len(ruleListMap) > 0 {
        for _, rv := range ruleListMap {
            rule := rv["Rule"].(map[string]any)

            cas.AddPolicy(rv["group_id"].(string), rule["url"].(string), rule["method"].(string))
        }
    }

    // 添加权限
    if len(groupListMap) > 0 {
        for _, gv := range groupListMap {
            cas.AddRoleForUser(gv["admin_id"].(string), gv["group_id"].(string))
        }
    }

    this.Success(ctx, "权限同步成功")
}

