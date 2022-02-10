package jwt

import (
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/helper"
    "github.com/deatil/lakego-doak/lakego/support/hash"
)

// 获取接收方
func GetJwtAud(ctx *router.Context) string {
    aud := hash.MD5(helper.GetRequestIp(ctx) + helper.GetHeaderByName(ctx, "HTTP_USER_AGENT"))

    return aud
}
