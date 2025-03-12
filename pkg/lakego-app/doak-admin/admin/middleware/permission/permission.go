package permission

import (
    "strings"
    gourl "net/url"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade"

    "github.com/deatil/lakego-doak-admin/admin/auth/admin"
    "github.com/deatil/lakego-doak-admin/admin/support/url"
    "github.com/deatil/lakego-doak-admin/admin/support/except"
    "github.com/deatil/lakego-doak-admin/admin/support/response"
    "github.com/deatil/lakego-doak-admin/admin/support/http/code"
)

/**
 * 权限检测
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        // 权限检测
        if shouldPassThrough(ctx) || permissionCheck(ctx) {
            ctx.Next()
        }

    }
}

// 权限检测
func permissionCheck(ctx *router.Context) bool {
    if checkSuperAdmin(ctx) {
        return true
    }

    requestPath := ctx.Request.URL.String()
    method := strings.ToUpper(ctx.Request.Method)

    adminId, ok := ctx.Get("admin_id")
    if !ok {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    }

    // 去除自定义分组前缀
    requestPaths := strings.Split(requestPath, "/")
    newRequestPaths := requestPaths[2:]

    newRequestPath := "/" + strings.Join(newRequestPaths, "/")

    // 解析地址
    u, _ := gourl.Parse(newRequestPath)
    newRequestPath = u.Path

    // 先匹配分组
    group := facade.Config("admin").GetString("route.prefix")
    if requestPaths[1] != group {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    }

    ok2, err2 := facade.Permission.Enforce(adminId.(string), newRequestPath, method)

    if err2 != nil {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    } else if !ok2 {
        response.Error(ctx, "你没有访问权限", code.AuthError)
        return false
    }

    return true
}

// 超级管理员检测
func checkSuperAdmin(ctx *router.Context) bool {
    adminInfo, _ := ctx.Get("admin")

    if adminInfo == nil {
        return false
    }

    isSuperAdministrator := adminInfo.(*admin.Admin).IsSuperAdministrator()
    if isSuperAdministrator {
        return true
    }

    return false
}

// 过滤
func shouldPassThrough(ctx *router.Context) bool {
    // 默认
    defaultExcepts := []string{
        "GET:passport/captcha",
        "POST:passport/login",
        "DELETE:passport/logout",
        "PUT:passport/refresh-token",
        "GET:attachment/download/*",
    }

    // 自定义
    configExcepts := facade.Config("auth").GetStringSlice("auth.permission-excepts")

    // 额外定义
    setExcepts := except.GetPermissionExcepts()

    // 合并
    excepts := append(defaultExcepts, configExcepts...)
    excepts = append(excepts, setExcepts...)

    // 只检测 url 中的 path 部分
    urlPath := ctx.Request.URL.String()

    u, _ := gourl.Parse(urlPath)
    urlPath = u.Path

    for _, ae := range excepts {
        newStr := strings.SplitN(ae, ":", 2)

        newUrl := newStr[0] + ":" + url.AdminUrl(newStr[1])
        if url.MatchPath(ctx, newUrl, urlPath) {
            return true
        }
    }

    return false
}
