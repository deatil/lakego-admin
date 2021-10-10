package permission

import (
    "strings"
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/http/response"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/facade/permission"

    "github.com/deatil/lakego-admin/admin/auth/admin"
    "github.com/deatil/lakego-admin/admin/support/url"
    "github.com/deatil/lakego-admin/admin/support/except"
    "github.com/deatil/lakego-admin/admin/support/http/code"
)

/**
 * 权限检测
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        if !shouldPassThrough(ctx) {
            // 权限检测
            permissionCheck(ctx)
        }

        ctx.Next()
    }
}

// 权限检测
func permissionCheck(ctx *gin.Context) bool {
    if checkSuperAdmin(ctx) {
        return true
    }

    requestPath := ctx.Request.URL.String()
    method := strings.ToUpper(ctx.Request.Method)

    adminId, _ := ctx.Get("admin_id")

    // 去除自定义分组前缀
    requestPaths := strings.Split(requestPath, "/")
    newRequestPaths := requestPaths[2:]
    newRequestPath := "/" + strings.Join(newRequestPaths, "/")

    // 先匹配分组
    group := config.New("admin").GetString("Route.Prefix")
    if requestPaths[1] != group {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    }

    c := permission.New()
    ok, err := c.Enforce(adminId.(string), newRequestPath, method)

    if err != nil {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    } else if !ok {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    }

    return true
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

// 过滤
func shouldPassThrough(ctx *gin.Context) bool {
    // 默认
    defaultExcepts := []string{
        "GET:passport/captcha",
        "POST:passport/login",
        "DELETE:passport/logout",
        "PUT:passport/refresh-token",
        "GET:attachment/download/*",
    }

    // 自定义
    configExcepts := config.New("auth").GetStringSlice("Auth.PermissionExcepts")

    // 额外定义
    setExcepts := except.GetPermissionExcepts()

    // 合并
    excepts := append(defaultExcepts, configExcepts...)
    excepts = append(excepts, setExcepts...)

    for _, ae := range excepts {
        newStr := strings.SplitN(ae, ":", 2)

        newUrl := newStr[0] + ":" + url.AdminUrl(newStr[1])
        if url.MatchPath(ctx, newUrl, "") {
            return true
        }
    }

    return false
}
