package controller

import (
    "github.com/gin-gonic/gin"
)

/**
 * 权限分组
 *
 * @create 2021-9-12
 * @author deatil
 */
type AuthGroup struct {
    Base
}

/**
 * 列表
 */
func (control *AuthGroup) Index(ctx *gin.Context) {

    control.SuccessWithData(ctx, "获取成功", gin.H{})
}
