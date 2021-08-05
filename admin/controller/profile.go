package controller

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/http/controller"
    "lakego-admin/lakego/facade/storage"
    "lakego-admin/admin/auth/admin"
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
 * 修改我的信息
 */
func (control *ProfileController) Update(ctx *gin.Context) {
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

    mime := storage.New().Copy("/log/123.log", "/log/log22/111.log")

    control.SuccessWithData(ctx, "获取成功", gin.H{
        "list": rules,
        "url": mime,
    })
}
