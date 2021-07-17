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
    jwtObj := ctx.GetHeader("Authorization")
    if jwtObj == "" {
        response.Error(ctx, code.JwtTokenInvalid, "token不能为空")
        return
    }

    // 授权 token
    accessToken := strings.Split(jwtObj, "Bearer ")[1]

    jwter := auth.New(ctx)

    // 解析 token
    claims, err := jwter.GetAccessTokenClaims(accessToken)
    if err != nil {
        response.Error(ctx, code.JwtAccessTokenFail, "token 已过期")
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
        response.Error(ctx, code.JwtTokenInvalid, "账号不存在或者被禁用")
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

    ctx.Set("admin_id", userId)
    ctx.Set("access_token", accessToken)
    ctx.Set("admin", adminer)
    ctx.Next()
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
            newUtl := newStr[0] + ":" + lake.AdminUrl(newStr[1])
            if lake.MatchPath(context, newUtl, "") {
                return true
            }
        }
    }

    return false
}
