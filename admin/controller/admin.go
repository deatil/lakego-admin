package controller

import (
    "github.com/gin-gonic/gin"
)

/**
 * 管理员
 *
 * @create 2021-9-2
 * @author deatil
 */
type Admin struct {
    Base
}

/**
 * 列表
 */
func (control *Admin) Index(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 详情
 */
func (control *Admin) Detail(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 管理员权限
 */
func (control *Admin) Rules(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 删除
 */
func (control *Admin) Delete(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 添加
 */
func (control *Admin) Create(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 更新
 */
func (control *Admin) Update(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 修改头像
 */
func (control *Admin) UpdateAvatar(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 修改密码
 */
func (control *Admin) UpdatePasssword(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 授权
 */
func (control *Admin) Access(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 启用
 */
func (control *Admin) Enable(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 禁用
 */
func (control *Admin) Disable(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

/**
 * 退出
 */
func (control *Admin) Logout(ctx *gin.Context) {

    // 数据输出
    control.SuccessWithData(ctx, "获取成功", gin.H{})
}

