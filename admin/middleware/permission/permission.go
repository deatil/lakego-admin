package permission

import (
    "strings"
    "github.com/gin-gonic/gin"
    "lakego-admin/lakego/facade/casbin"
    "lakego-admin/lakego/http/code"
    "lakego-admin/lakego/http/response"
)

// 权限检测
func Permission() gin.HandlerFunc {
    return func(c *gin.Context) {
        requestPath := ctx.FullPath()
        method := strings.ToUpper(ctx.Request.Method)
        adminId := c.Get("admin_id")
        
        c := casbin.New()
        ok, err := c.Enforce(adminId, requestPath, method)
        
        if err != nil {
            response.Error(ctx, code.AuthError, "你没有访问权限")
            return 
        } else if !ok {
            response.Error(ctx, code.AuthError, "你没有访问权限")
            return 
        }
            
        c.Next()
    }
}
