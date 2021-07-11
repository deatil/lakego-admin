package router

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/admin/controller"
)

/**
 * 后台路由
 */
func Route(engine *gin.RouterGroup) {
    // 登陆
    passportController := new(controller.PassportController)
    engine.GET("/passport/captcha", passportController.Captcha)
    engine.POST("/passport/login", passportController.Login)
    engine.PUT("/passport/refresh-token", passportController.RefreshToken)
    engine.DELETE("/passport/logout", passportController.Logout)

    // 个人信息
    profileController := new(controller.ProfileController)
    engine.GET("/profile", profileController.Index)
    engine.PUT("/profile/update", profileController.Update)
    engine.PATCH("/profile/avatar", profileController.UpdateAvatar)
    engine.PATCH("/profile/password", profileController.UpdatePasssword)
    engine.GET("/profile/rules", profileController.Rules)
}
