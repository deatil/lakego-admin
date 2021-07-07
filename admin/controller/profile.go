package controller

import (
	"github.com/gin-gonic/gin"

	"lakego-admin/lakego/http/controller"
    "lakego-admin/admin/auth/admin"
)

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
