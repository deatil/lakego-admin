package controller

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/event"
    "lakego-admin/lakego/http/controller"
    authPassword "lakego-admin/lakego/auth/password"
    "lakego-admin/admin/model"
    "lakego-admin/admin/auth/admin"
    profileValidate "lakego-admin/admin/validate/profile"
)

/**
 * 个人信息
 *
 * @create 2021-7-5
 * @author deatil
 */
type ProfileController struct {
    controller.BaseController
}

/**
 * 个人信息
 */
func (control *ProfileController) Index(ctx *gin.Context) {
    adminInfo, _ := ctx.Get("admin")

    adminInfo = adminInfo.(*admin.Admin).GetProfile()

    control.SuccessWithData(ctx, "获取成功", adminInfo)
}

/**
 * 修改信息
 */
func (control *ProfileController) Update(ctx *gin.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 检测
    validateErr := profileValidate.Update(post)
    if validateErr != "" {
        control.Error(ctx, validateErr)
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
        control.Error(ctx, "修改信息失败")
        return
    }

    // 事件
    event.ContextDispatch(ctx, "ProfileUpdateAfter", adminid)

    control.Success(ctx, "修改信息成功")
}

/**
 * 修改头像
 */
func (control *ProfileController) UpdateAvatar(ctx *gin.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 检测
    validateErr := profileValidate.UpdateAvatar(post)
    if validateErr != "" {
        control.Error(ctx, validateErr)
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
        control.Error(ctx, "修改头像失败")
        return
    }

    // 事件
    event.ContextDispatch(ctx, "ProfileUpdateAvatarAfter", adminid)

    control.Success(ctx, "修改头像成功")
}

/**
 * 修改密码
 */
func (control *ProfileController) UpdatePasssword(ctx *gin.Context) {
    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 检测
    validateErr := profileValidate.UpdatePasssword(post)
    if validateErr != "" {
        control.Error(ctx, validateErr)
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
        control.Error(ctx, "两次密码输入不一致")
        return
    }

    // 验证密码
    checkStatus := authPassword.CheckPassword(admin["password"].(string), oldpassword, admin["password_salt"].(string))
    if !checkStatus {
        control.Error(ctx, "用户密码错误")
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
        control.Error(ctx, "密码修改失败")
        return
    }

    // 事件
    event.ContextDispatch(ctx, "ProfileUpdatePassswordAfter", adminid)

    control.Success(ctx, "密码修改成功")
}

/**
 * 权限列表
 */
func (control *ProfileController) Rules(ctx *gin.Context) {
    rules := make(map[string]string)

    control.SuccessWithData(ctx, "获取成功", gin.H{
        "list": rules,
    })
}
