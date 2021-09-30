package authorization

import (
    "strings"
    "encoding/json"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/http/response"
    "lakego-admin/lakego/facade/auth"
    "lakego-admin/lakego/facade/config"

    "lakego-admin/admin/auth/admin"
    "lakego-admin/admin/support/url"
    "lakego-admin/admin/support/jwt"
    "lakego-admin/admin/support/except"
    "lakego-admin/admin/support/http/code"
    "lakego-admin/admin/model"
)

/**
 * 检查 token 权限
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        if !shouldPassThrough(ctx) {
            // 权限检测
            jwtCheck(ctx)
        }

        ctx.Next()
    }
}

// 路由中间件
func jwtCheck(ctx *gin.Context) {
    authJwt := ctx.GetHeader("Authorization")
    if authJwt == "" {
        response.Error(ctx, "token不能为空", code.JwtTokenInvalid)
        return
    }

    prefix := "Bearer "
    if !strings.HasPrefix(authJwt, prefix) {
        response.Error(ctx, "token 错误", code.JwtTokenInvalid)
        return
    }

    // 授权 token
    accessToken := strings.TrimPrefix(authJwt, prefix)

    aud := jwt.GetJwtAud(ctx)
    jwter := auth.NewWithAud(aud)

    // 解析 token
    claims, err := jwter.GetAccessTokenClaims(accessToken)
    if err != nil {
        response.Error(ctx, "token 已过期", code.JwtAccessTokenFail)
        return
    }

    // 用户ID
    userId := jwter.GetDataFromTokenClaims(claims, "id")

    // 用户信息
    adminInfo := new(model.Admin)
    modelErr := model.NewAdmin().
        Where(&model.Admin{ID: userId}).
        Preload("Groups").
        First(&adminInfo).
        Error
    if modelErr != nil {
        response.Error(ctx, "账号不存在或者被禁用", code.JwtTokenInvalid)
        return
    }

    // 结构体转map
    data, _ := json.Marshal(&adminInfo)
    adminData := map[string]interface{}{}
    json.Unmarshal(data, &adminData)

    // 头像
    adminData["avatar"] = model.AttachmentUrl(adminData["avatar"].(string))

    adminer := admin.New()
    adminer.WithAccessToken(accessToken).
        WithId(userId).
        WithData(adminData)

    // 是否激活
    if !adminer.IsActive() {
        response.Error(ctx, "帐号不存在或者已被锁定", code.AuthError)
        return
    }

    // 所属分组是否激活
    if !adminer.IsGroupActive() {
        response.Error(ctx, "帐号用户组不存在或者已被锁定", code.AuthError)
        return
    }

    ctx.Set("admin_id", userId)
    ctx.Set("access_token", accessToken)
    ctx.Set("admin", adminer)
}

// 过滤
func shouldPassThrough(ctx *gin.Context) bool {
    // 默认
    defaultExcepts := []string{
        "GET:passport/captcha",
        "POST:passport/login",
        "PUT:passport/refresh-token",
        "GET:attachment/download/*",
    }

    // 自定义
    configExcepts := config.New("auth").GetStringSlice("Auth.AuthenticateExcepts")

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
