package authorization

import (
    "strings"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade"

    "github.com/deatil/lakego-doak-admin/admin/auth/auth"
    "github.com/deatil/lakego-doak-admin/admin/auth/admin"
    "github.com/deatil/lakego-doak-admin/admin/support/url"
    "github.com/deatil/lakego-doak-admin/admin/support/except"
    "github.com/deatil/lakego-doak-admin/admin/support/response"
    "github.com/deatil/lakego-doak-admin/admin/support/http/code"
    "github.com/deatil/lakego-doak-admin/admin/model"
)

/**
 * 检查 token 权限
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        // 权限检测
        if shouldPassThrough(ctx) || jwtCheck(ctx) {
            ctx.Next()
        }
    }
}

// 路由中间件
func jwtCheck(ctx *router.Context) bool {
    authJwt := ctx.GetHeader("Authorization")
    if authJwt == "" {
        response.Error(ctx, "token不能为空", code.JwtTokenInvalid)
        return false
    }

    prefix := "Bearer "
    if !strings.HasPrefix(authJwt, prefix) {
        response.Error(ctx, "token 错误", code.JwtTokenInvalid)
        return false
    }

    // 授权 token
    accessToken := strings.TrimPrefix(authJwt, prefix)

    aud := auth.GetJwtAud(ctx)
    jwter := auth.NewWithAud(aud)

    // 解析 token
    claims, err := jwter.GetAccessTokenClaims(accessToken)
    if err != nil {
        response.Error(ctx, "token 已过期", code.JwtAccessTokenFail)
        return false
    }

    // 用户ID
    userId := jwter.GetDataFromTokenClaims(claims, "id")

    // 用户信息
    adminInfo := new(model.Admin)
    modelErr := model.NewDB().
        Where(&model.Admin{ID: userId}).
        Preload("Groups").
        First(&adminInfo).
        Error
    if modelErr != nil {
        response.Error(ctx, "账号不存在或者被禁用", code.JwtTokenInvalid)
        return false
    }

    // 结构体转map
    adminData := model.FormatStructToMap(adminInfo)

    adminer := admin.New()
    adminer.WithAccessToken(accessToken).
        WithId(userId).
        WithData(adminData)

    // 是否激活
    if !adminer.IsActive() {
        response.Error(ctx, "帐号不存在或者已被锁定", code.AuthError)
        return false
    }

    // 所属分组是否激活
    if !adminer.IsGroupActive() {
        response.Error(ctx, "帐号用户组不存在或者已被锁定", code.AuthError)
        return false
    }

    ctx.Set("admin_id", userId)
    ctx.Set("access_token", accessToken)
    ctx.Set("admin", adminer)

    return true
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
    configExcepts := facade.Config("auth").GetStringSlice("auth.authenticate-excepts")

    // 额外定义
    setExcepts := except.GetPermissionExcepts()

    // 合并
    excepts := append(defaultExcepts, configExcepts...)
    excepts = append(excepts, setExcepts...)

    // 只检测 url 中的 path 部分
    urlPath := ctx.Request.URL.String()
    urlPaths := strings.Split(urlPath, "?")

    for _, ae := range excepts {
        newStr := strings.SplitN(ae, ":", 2)

        newUrl := newStr[0] + ":" + url.AdminUrl(newStr[1])
        if url.MatchPath(ctx, newUrl, urlPaths[0]) {
            return true
        }
    }

    return false
}
