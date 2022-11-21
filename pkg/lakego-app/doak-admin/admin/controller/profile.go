package controller

import (
    "github.com/deatil/go-event/event"
    
    "github.com/deatil/lakego-doak/lakego/router"
    authPassword "github.com/deatil/lakego-doak/lakego/auth/password"

    "github.com/deatil/lakego-doak-admin/admin/model"
    "github.com/deatil/lakego-doak-admin/admin/auth/admin"
    profileValidate "github.com/deatil/lakego-doak-admin/admin/validate/profile"
)

/**
 * 个人信息
 *
 * @create 2021-7-5
 * @author deatil
 */
type Profile struct {
    Base
}

// 个人信息
// @Summary 个人信息详情
// @Description 个人信息详情
// @Tags 个人信息
// @Accept  application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /profile [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.profile.index"}
func (this *Profile) Index(ctx *router.Context) {
    adminInfo, ok := ctx.Get("admin")
    if !ok {
        this.Error(ctx, "获取失败")
        return
    }

    adminProfile := adminInfo.(*admin.Admin).GetProfile()

    this.SuccessWithData(ctx, "获取成功", adminProfile)
}

// 修改信息
// @Summary 修改个人信息详情
// @Description 修改个人信息详情
// @Tags 个人信息
// @Accept  application/json
// @Produce application/json
// @Param nickname  formData string true "昵称"
// @Param email     formData string true "邮箱"
// @Param introduce formData string true "简介"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /profile [put]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.profile.update"}
func (this *Profile) Update(ctx *router.Context) {
    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 检测
    validateErr := profileValidate.Update(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    // 当前账号信息
    adminInfo, ok := ctx.Get("admin")
    if !ok {
        this.Error(ctx, "修改信息失败")
        return
    }

    adminid := adminInfo.(*admin.Admin).GetId()

    err := model.NewAdmin().
        Where("id = ?", adminid).
        Updates(map[string]any{
            "nickname": post["nickname"].(string),
            "email": post["email"].(string),
            "introduce": post["introduce"].(string),
        }).
        Error
    if err != nil {
        this.Error(ctx, "修改信息失败")
        return
    }

    // 事件
    event.Dispatch("profile.update-after", adminid)

    this.Success(ctx, "修改信息成功")
}

// 修改头像
// @Summary 修改个人头像
// @Description 修改个人头像
// @Tags 个人信息
// @Accept  application/json
// @Produce application/json
// @Param avatar formData string true "头像数据ID"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /profile/avatar [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.profile.avatar"}
func (this *Profile) UpdateAvatar(ctx *router.Context) {
    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 检测
    validateErr := profileValidate.UpdateAvatar(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    // 当前账号信息
    adminInfo, ok := ctx.Get("admin")
    if !ok {
        this.Error(ctx, "修改头像失败")
        return
    }

    adminid := adminInfo.(*admin.Admin).GetId()

    err := model.NewAdmin().
        Where("id = ?", adminid).
        Updates(map[string]any{
            "avatar": post["avatar"].(string),
        }).
        Error
    if err != nil {
        this.Error(ctx, "修改头像失败")
        return
    }

    // 事件
    event.Dispatch("profile.update-avatar-after", adminid)

    this.Success(ctx, "修改头像成功")
}

// 修改密码
// @Summary 修改密码
// @Description 修改密码
// @Tags 个人信息
// @Accept  application/json
// @Produce application/json
// @Param oldpassword         formData string true "旧密码"
// @Param newpassword         formData string true "新密码"
// @Param newpassword_confirm formData string true "确认新密码"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /profile/password [patch]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.profile.password"}
func (this *Profile) UpdatePasssword(ctx *router.Context) {
    // 接收数据
    post := make(map[string]any)
    this.ShouldBindJSON(ctx, &post)

    // 检测
    validateErr := profileValidate.UpdatePasssword(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    // 当前账号信息
    adminInfo, ok := ctx.Get("admin")
    if !ok {
        this.Error(ctx, "密码修改失败")
        return
    }

    // 登陆账号信息
    adminData := adminInfo.(*admin.Admin)

    adminid := adminData.GetId()
    admin := adminData.GetData()

    oldpassword := post["oldpassword"].(string)
    newpassword := post["newpassword"].(string)
    newpasswordConfirm := post["newpassword_confirm"].(string)

    if newpassword != newpasswordConfirm {
        this.Error(ctx, "两次密码输入不一致")
        return
    }

    // 验证密码
    checkStatus := authPassword.CheckPassword(admin["password"].(string), oldpassword, admin["password_salt"].(string))
    if !checkStatus {
        this.Error(ctx, "用户密码错误")
        return
    }

    // 生成密码
    pass, encrypt := authPassword.MakePassword(newpassword)

    err := model.NewAdmin().
        Where("id = ?", adminid).
        Updates(map[string]any{
            "password": pass,
            "password_salt": encrypt,
        }).
        Error
    if err != nil {
        this.Error(ctx, "密码修改失败")
        return
    }

    // 事件
    event.Dispatch("profile.update-passsword-after", adminid)

    this.Success(ctx, "密码修改成功")
}

// 个人权限列表
// @Summary 个人权限列表
// @Description 个人权限列表
// @Tags 个人信息
// @Accept  application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /profile/rules [get]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.profile.rules"}
func (this *Profile) Rules(ctx *router.Context) {
    adminInfo, ok := ctx.Get("admin")
    if !ok {
        this.Error(ctx, "获取失败")
        return
    }

    rules := adminInfo.(*admin.Admin).GetRules()

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": rules,
    })
}
