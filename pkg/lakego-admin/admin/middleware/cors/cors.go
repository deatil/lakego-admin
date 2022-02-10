package cors

import (
    "strings"
    "net/http"

    "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/facade/config"
)

/**
 * 跨域处理
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        if isTrueRequest(ctx) {
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
                    ctx.AbortWithStatus(http.StatusOK)

                    return
                }
            }
        }

        ctx.Next()
    }
}

// 系统请求检测
func isTrueRequest(ctx *router.Context) bool {
    // 前缀匹配
    path := "/" + config.New("admin").GetString("Route.Prefix")

    url := ctx.Request.URL.String()

    if strings.HasPrefix(url, path) {
        return true
    }

    return false
}

