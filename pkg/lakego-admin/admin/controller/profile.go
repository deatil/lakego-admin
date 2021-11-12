package controller

import (
    "github.com/deatil/lakego-admin/lakego/event"
    "github.com/deatil/lakego-admin/lakego/router"
    authPassword "github.com/deatil/lakego-admin/lakego/auth/password"

    "github.com/deatil/lakego-admin/admin/model"
    "github.com/deatil/lakego-admin/admin/auth/admin"
    profileValidate "github.com/deatil/lakego-admin/admin/validate/profile"
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

/**
 * 个人信息
 */
func (this *Profile) Index(ctx *router.Context) {
    adminInfo, _ := ctx.Get("admin")

    adminInfo = adminInfo.(*admin.Admin).GetProfile()

    this.SuccessWithData(ctx, "获取成功", adminInfo)
}

/**
 * 修改信息
 */
func (this *Profile) Update(ctx *router.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 检测
    validateErr := profileValidate.Update(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    // 当前账号信息
    adminInfo, _ := ctx.Get("admin")
    adminid := adminInfo.(*admin.Admin).GetId()

    err := model.NewAdmin().
        Where("id = ?", adminid).
        Updates(map[string]interface{}{
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
    event.ContextDispatch(ctx, "ProfileUpdateAfter", adminid)

    this.Success(ctx, "修改信息成功")
}

/**
 * 修改头像
 */
func (this *Profile) UpdateAvatar(ctx *router.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 检测
    validateErr := profileValidate.UpdateAvatar(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    // 当前账号信息
    adminInfo, _ := ctx.Get("admin")
    adminid := adminInfo.(*admin.Admin).GetId()

    err := model.NewAdmin().
        Where("id = ?", adminid).
        Updates(map[string]interface{}{
            "avatar": post["avatar"].(string),
        }).
        Error
    if err != nil {
        this.Error(ctx, "修改头像失败")
        return
    }

    // 事件
    event.ContextDispatch(ctx, "ProfileUpdateAvatarAfter", adminid)

    this.Success(ctx, "修改头像成功")
}

/**
 * 修改密码
 */
func (this *Profile) UpdatePasssword(ctx *router.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 检测
    validateErr := profileValidate.UpdatePasssword(post)
    if validateErr != "" {
        this.Error(ctx, validateErr)
        return
    }

    // 当前账号信息
    adminInfo, _ := ctx.Get("admin")
    adminid := adminInfo.(*admin.Admin).GetId()
    admin := adminInfo.(*admin.Admin).GetData()

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
        Updates(map[string]interface{}{
            "password": pass,
            "password_salt": encrypt,
        }).
        Error
    if err != nil {
        this.Error(ctx, "密码修改失败")
        return
    }

    // 事件
    event.ContextDispatch(ctx, "ProfileUpdatePassswordAfter", adminid)

    this.Success(ctx, "密码修改成功")
}

/**
 * 权限列表
 */
func (this *Profile) Rules(ctx *router.Context) {
    adminInfo, _ := ctx.Get("admin")
    rules := adminInfo.(*admin.Admin).GetRules()

    this.SuccessWithData(ctx, "获取成功", router.H{
        "list": rules,
    })
}
