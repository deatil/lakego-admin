package controller

import (
    "github.com/gin-gonic/gin"
)

/**
 * 菜单权限
 *
 * @create 2021-9-12
 * @author deatil
 */
type AuthRule struct {
    Base
}

/**
 * 列表
 */
func (control *AuthRule) Index(ctx *gin.Context) {

    control.SuccessWithData(ctx, "获取成功", gin.H{})
}
