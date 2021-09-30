package cors

import (
    "net/http"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/facade/config"
)

/**
 * 跨域处理
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        conf := config.New("cors")
        open := conf.GetBool("OpenAllowOrigin")

        if (open) {
            ctx.Header("Access-Control-Allow-Origin", conf.GetString("AllowOrigin"))

            ctx.Header("Access-Control-Allow-Headers", conf.GetString("AllowHeaders"))
            ctx.Header("Access-Control-Allow-Methods", conf.GetString("AllowMethods"))
            ctx.Header("Access-Control-Expose-Headers", conf.GetString("AllowHeaders"))

            allowCredentials := conf.GetBool("AllowCredentials")
            if (allowCredentials) {
                ctx.Header("Access-Control-Allow-Credentials", "true")
            }

            // 放行所有OPTIONS方法
            method := ctx.Request.Method
            if method == "OPTIONS" {
                ctx.AbortWithStatus(http.StatusAccepted)
            }
        }

        ctx.Next()
    }
}
