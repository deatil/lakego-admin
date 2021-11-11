package admincheck

import (
    gin "github.com/deatil/lakego-admin/lakego/router"

    "github.com/deatil/lakego-admin/admin/auth/admin"
    "github.com/deatil/lakego-admin/admin/support/response"
    "github.com/deatil/lakego-admin/admin/support/http/code"
)

/**
 * 超级管理员检测
 *
 * @create 2021-9-30
 * @author deatil
 */
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        isSuperAdministrator := checkSuperAdmin(ctx)
        if !isSuperAdministrator {
            response.Error(ctx, "你没有权限进行该操作", code.AuthError)
            return
        }

        ctx.Next()
    }
}

// 超级管理员检测
func checkSuperAdmin(ctx *gin.Context) bool {
    adminInfo, _ := ctx.Get("admin")

    if adminInfo == nil {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    }

    isSuperAdministrator := adminInfo.(*admin.Admin).IsSuperAdministrator()
    if isSuperAdministrator {
        return true
    }

    return false
}
