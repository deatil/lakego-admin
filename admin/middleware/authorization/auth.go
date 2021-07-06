package authorization

import (
	"strings"
	"github.com/gin-gonic/gin"
	
	"lakego-admin/lakego/config"
	"lakego-admin/lakego/lake"
	"lakego-admin/lakego/auth/middleware"
)

// 检查token权限
func CheckTokenAuth() gin.HandlerFunc {
	return func(context *gin.Context) {
		if !shouldPassThrough(context) {
			// 权限检测
			middleware.JWTCheck(context)
		}
		
		context.Next()
	}
}

// 过滤
func shouldPassThrough(context *gin.Context) bool {
	// 默认过滤
	excepts := []string{
		"GET:" + lake.AdminUrl("passport/captcha"),
		"POST:" + lake.AdminUrl("passport/login"),
		"POST:" + lake.AdminUrl("passport/refresh-token"),
	}
	for _, e := range excepts {
		if lake.MatchPath(context, e, "") {
			return true
		}
	}
	
	// 自定义权限过滤
	authenticateExcepts := config.NewConfig("auth").GetStringSlice("Auth.AuthenticateExcepts")
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