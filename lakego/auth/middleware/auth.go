package middleware

import (
	"strings"
    "github.com/gin-gonic/gin"
	
	"lakego-admin/lakego/auth"
	"lakego-admin/lakego/http/code"
	"lakego-admin/lakego/http/response"
)

// 路由中间件
// "lakego-admin/lakego/auth/middleware"
func JWTCheck(ctx *gin.Context) {
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
		response.Error(ctx, code.JwtAccessTokenFail, err.Error())
		return 
	}
	
	// 用户ID
	userId := jwter.GetDataFromTokenClaims(claims, "id")
	
    ctx.Set("admin_id", userId)
    ctx.Set("access_token", accessToken)
    ctx.Next()
}