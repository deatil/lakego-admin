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
    passportController := new(controller.Passport)
    engine.GET("/passport/captcha", passportController.Captcha)
    engine.POST("/passport/login", passportController.Login)
    engine.PUT("/passport/refresh-token", passportController.RefreshToken)
    engine.DELETE("/passport/logout", passportController.Logout)

    // 个人信息
    profileController := new(controller.Profile)
    engine.GET("/profile", profileController.Index)
    engine.PUT("/profile/update", profileController.Update)
    engine.PATCH("/profile/avatar", profileController.UpdateAvatar)
    engine.PATCH("/profile/password", profileController.UpdatePasssword)
    engine.GET("/profile/rules", profileController.Rules)

    // 上传
    uploadController := new(controller.Upload)
    engine.POST("/upload/file", uploadController.File)

    // 附件
    attachmentController := new(controller.Attachment)
    engine.GET("/attachment", attachmentController.Index)
    engine.GET("/attachment/:id", attachmentController.Detail)
    engine.PATCH("/attachment/:id/enable", attachmentController.Enable)
    engine.PATCH("/attachment/:id/disable", attachmentController.Disable)
    engine.DELETE("/attachment/:id", attachmentController.Delete)
    engine.GET("/attachment/downcode/:id", attachmentController.DownloadCode)
    engine.GET("/attachment/download/:code", attachmentController.Download)

    // 管理员
    adminController := new(controller.Admin)
    engine.GET("/admin", adminController.Index)
    engine.GET("/admin/groups", adminController.Groups)
    engine.GET("/admin/:id", adminController.Detail)
    engine.GET("/admin/:id/rules", adminController.Rules)
    engine.POST("/admin", adminController.Create)
    engine.PUT("/admin/:id", adminController.Update)
    engine.DELETE("/admin/:id", adminController.Delete)
    engine.PATCH("/admin/:id/enable", adminController.Enable)
    engine.PATCH("/admin/:id/disable", adminController.Disable)
    engine.PATCH("/admin/:id/avatar", adminController.UpdateAvatar)
    engine.PATCH("/admin/:id/password", adminController.UpdatePasssword)
    engine.PATCH("/admin/:id/access", adminController.Access)
    engine.DELETE("/admin/logout/:refreshToken", adminController.Logout)
}
