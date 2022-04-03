package jwt

import (
    "github.com/deatil/go-hash/hash"
    "github.com/deatil/lakego-doak/lakego/router"
)

// 获取接收方
func GetJwtAud(ctx *router.Context) string {
    aud := hash.MD5(router.GetRequestIp(ctx) + router.GetHeaderByName(ctx, "HTTP_USER_AGENT"))

    return aud
}
