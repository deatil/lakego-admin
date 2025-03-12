package cors

import (
    "strings"
    "net/http"

    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade"
)

/**
 * 跨域处理
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        // 域名
        origin := ctx.GetHeader("Origin")

        if len(origin) > 0 && isTrueRequest(ctx) {
            conf := facade.Config("cors")
            open := conf.GetBool("open-allow-origin")

            if (open) {
                ctx.Header("Access-Control-Allow-Origin", conf.GetString("allow-origin"))

                ctx.Header("Access-Control-Allow-Headers", conf.GetString("allow-headers"))
                ctx.Header("Access-Control-Allow-Methods", conf.GetString("allow-methods"))
                ctx.Header("Access-Control-Expose-Headers", conf.GetString("expose-headers"))

                allowCredentials := conf.GetBool("allow-credentials")
                if (allowCredentials) {
                    ctx.Header("Access-Control-Allow-Credentials", "true")
                }

                maxAge := conf.GetString("max-age")
                if maxAge != "" {
                    ctx.Header("Access-Control-Max-Age", maxAge)
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
    path := "/" + facade.Config("admin").GetString("Route.Prefix")

    url := ctx.Request.URL.String()

    if strings.HasPrefix(url, path) {
        return true
    }

    return false
}

