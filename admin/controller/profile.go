package controller

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/controller"
    "lakego-admin/admin/auth/admin"
    "lakego-admin/admin/model"
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
        control.Error(ctx, validateErr, code.StatusError)
        return
    }

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
        control.Error(ctx, "修改信息失败", code.StatusError)
        return
    }

    control.Success(ctx, "修改信息成功")
}

/**
 * 修改头像
 */
func (control *ProfileController) UpdateAvatar(ctx *gin.Context) {
    control.Success(ctx, "修改头像成功")
}

/**
 * 修改密码
 */
func (control *ProfileController) UpdatePasssword(ctx *gin.Context) {
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
