package actionlog

import (
    "strings"
    "encoding/json"
    "github.com/gin-gonic/gin"

    "github.com/deatil/lakego-admin/lakego/helper"
    "github.com/deatil/lakego-admin/lakego/support/time"

    "lakego-admin/admin/model"
)

/**
 * 操作日志
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        ctx.Next()

        go recordLog(ctx)
    }
}

// 记录日志
func recordLog(ctx *gin.Context) {
    adminId, _ := ctx.Get("admin_id")

    name := "操作账号[-]"
    if adminId != nil {
        name = "操作账号[" + adminId.(string) + "]"
    }

    url := ctx.Request.URL.String()
    method := strings.ToUpper(ctx.Request.Method)

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 请求数据
    info, _ := json.Marshal(&post)
    useragent := ctx.Request.Header.Get("User-Agent")

    ip := helper.GetRequestIp(ctx)

    // 记录数据
    model.NewDB().Create(&model.ActionLog{
        Name: name,
        Url: url,
        Method: method,
        Info: string(info),
        Useragent: useragent,
        Ip: ip,
        AddTime: time.NowTimeToInt(),
        AddIp: ip,
    })
}
