package cors

import (
    "net/http"
    "github.com/gin-gonic/gin"
    
    "lakego-admin/lakego/config"
)

// 允许跨域
func Cors() gin.HandlerFunc {
    return func(c *gin.Context) {
        conf := config.New("cors")
        open := conf.GetBool("OpenAllowOrigin")
        
        if (open) {
            c.Header("Access-Control-Allow-Origin", conf.GetString("AllowOrigin"))
            
            c.Header("Access-Control-Allow-Headers", conf.GetString("AllowHeaders"))
            c.Header("Access-Control-Allow-Methods", conf.GetString("AllowMethods"))
            c.Header("Access-Control-Expose-Headers", conf.GetString("AllowHeaders"))
            
            allowCredentials := conf.GetString("AllowCredentials")
            if (allowCredentials == "true") {
                c.Header("Access-Control-Allow-Credentials", "true")
            }
    
            // 放行所有OPTIONS方法
            method := c.Request.Method
            if method == "OPTIONS" {
                c.AbortWithStatus(http.StatusAccepted)
            }
        }

        c.Next()
    }
}
