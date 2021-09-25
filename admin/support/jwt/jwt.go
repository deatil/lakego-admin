package jwt

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/helper"
    "lakego-admin/lakego/support/hash"
)

// 获取接收方
func GetJwtAud(ctx *gin.Context) string {
    aud := hash.MD5(helper.GetRequestIp(ctx) + helper.GetHeaderByName(ctx, "HTTP_USER_AGENT"))

    return aud
}
