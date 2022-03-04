package controller

import (
    "github.com/gin-gonic/gin"
    // "github.com/deatil/lakego-doak/lakego/router"

    "github.com/deatil/lakego-doak-admin/admin/support/controller"
)

/**
 * 首页
 *
 * @create 2021-10-11
 * @author deatil
 */
type Index struct {
    controller.Base
}

// 首页信息
// @Summary 首页信息
// @Description 首页信息
// @Tags 例子
// @Accept application/json
// @Produce application/json
// @Success 200 {string} json "{"success": true, "code": 0, "message": "例子信息获取成功", "data": ""}"
// @Router /example/index [get]
// @Security Bearer
func (this *Index) Index(ctx *gin.Context) {
    this.Success(ctx, "例子信息获取成功")
}

