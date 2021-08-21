package authorization

import (
    "strings"
    "encoding/json"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/config"
    "lakego-admin/lakego/lake"
    "lakego-admin/lakego/auth"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/response"
    "lakego-admin/admin/model"
    "lakego-admin/admin/auth/admin"
)

// 检查token权限
func Handler() gin.HandlerFunc {
    return func(context *gin.Context) {
        if !shouldPassThrough(context) {
            // 权限检测
            jwtCheck(context)
        }

        context.Next()
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

    jwter := auth.New(ctx)

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
func shouldPassThrough(context *gin.Context) bool {
    // 默认过滤
    excepts := []string{
        "GET:" + lake.AdminUrl("passport/captcha"),
        "POST:" + lake.AdminUrl("passport/login"),
        "PUT:" + lake.AdminUrl("passport/refresh-token"),
    }
    for _, except := range excepts {
        if lake.MatchPath(context, except, "") {
            return true
        }
    }

    // 自定义权限过滤
    authenticateExcepts := config.New("auth").GetStringSlice("Auth.AuthenticateExcepts")
    for _, ae := range authenticateExcepts {
        newStr := strings.Split(ae, ":")
        if len(newStr) == 2 {
            newUrl := newStr[0] + ":" + lake.AdminUrl(newStr[1])
            if lake.MatchPath(context, newUrl, "") {
                return true
            }
        }
    }

    return false
}
