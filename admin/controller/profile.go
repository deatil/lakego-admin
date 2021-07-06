package controller

import (
	"github.com/gin-gonic/gin"
	
	"lakego-admin/lakego/http/controller"
)

type ProfileController struct {
	controller.BaseController
}

/**
 * 个人信息
 */
func (control *ProfileController) Index(context *gin.Context) {
	data := "个人数据"
	
    control.SuccessWithData(context, "获取成功", gin.H{
		"cache": data,
	})
}
