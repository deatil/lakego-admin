package route

import (
    "github.com/deatil/lakego-doak/lakego/router"

    "github.com/deatil/lakego-doak-admin/admin/controller"
)

/**
 * 后台路由
 */
func Route(engine *router.RouterGroup) {
    // 登陆
    passportController := new(controller.Passport)
    engine.GET("/passport/captcha", passportController.Captcha)
    engine.POST("/passport/login", passportController.Login)
    engine.PUT("/passport/refresh-token", passportController.RefreshToken)
    engine.DELETE("/passport/logout", passportController.Logout)

    // 个人信息
    profileController := new(controller.Profile)
    engine.GET("/profile", profileController.Index)
    engine.PUT("/profile", profileController.Update)
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
    engine.PUT("/admin/reset-permission", adminController.ResetPermission)

    // 系统信息
    systemController := new(controller.System)
    engine.GET("/system/info", systemController.Info)
    engine.GET("/system/rules", systemController.Rules)
}

/**
 * 后台管理员路由
 */
func AdminRoute(engine *router.RouterGroup) {
    // 权限菜单
    authRuleController := new(controller.AuthRule)
    engine.GET("/auth/rule", authRuleController.Index)
    engine.GET("/auth/rule/tree", authRuleController.IndexTree)
    engine.GET("/auth/rule/children", authRuleController.IndexChildren)
    engine.GET("/auth/rule/:id", authRuleController.Detail)
    engine.POST("/auth/rule", authRuleController.Create)
    engine.PUT("/auth/rule/:id", authRuleController.Update)
    engine.DELETE("/auth/rule/clear", authRuleController.Clear)
    engine.DELETE("/auth/rule/:id", authRuleController.Delete)
    engine.PATCH("/auth/rule/:id/sort", authRuleController.Listorder)
    engine.PATCH("/auth/rule/:id/enable", authRuleController.Enable)
    engine.PATCH("/auth/rule/:id/disable", authRuleController.Disable)

    // 权限分组
    authGroupController := new(controller.AuthGroup)
    engine.GET("/auth/group", authGroupController.Index)
    engine.GET("/auth/group/tree", authGroupController.IndexTree)
    engine.GET("/auth/group/children", authGroupController.IndexChildren)
    engine.GET("/auth/group/:id", authGroupController.Detail)
    engine.POST("/auth/group", authGroupController.Create)
    engine.PUT("/auth/group/:id", authGroupController.Update)
    engine.DELETE("/auth/group/:id", authGroupController.Delete)
    engine.PATCH("/auth/group/:id/sort", authGroupController.Listorder)
    engine.PATCH("/auth/group/:id/enable", authGroupController.Enable)
    engine.PATCH("/auth/group/:id/disable", authGroupController.Disable)
    engine.PATCH("/auth/group/:id/access", authGroupController.Access)
}
