package actionlog

import (
    "strconv"
    "encoding/json"

    "github.com/deatil/lakego-admin/lakego/router"
    "github.com/deatil/lakego-admin/lakego/helper"
    "github.com/deatil/lakego-admin/lakego/support/time"

    "github.com/deatil/lakego-admin/admin/model"
)

/**
 * 操作日志
 *
 * @create 2021-9-5
 * @author deatil
 */
func Handler() router.HandlerFunc {
    return func(ctx *router.Context) {
        ctx.Next()

        go recordLog(ctx)
    }
}

// 记录日志
func recordLog(ctx *router.Context) {
    adminId, _ := ctx.Get("admin_id")

    name := "操作账号[-]"
    if adminId != nil {
        name = "操作账号[" + adminId.(string) + "]"
    }

    url := ctx.Request.URL.String()
    method := ctx.Request.Method

    // path := ctx.Request.Path
    // query := ctx.Request.RawQuery

    // 接收数据
    post := make(map[string]interface{})
    ctx.BindJSON(&post)

    // 请求数据
    info, _ := json.Marshal(&post)
    useragent := ctx.Request.Header.Get("User-Agent")

    // 请求 IP
    ip := helper.GetRequestIp(ctx)

    // 响应输出状态
    status := strconv.Itoa(ctx.Writer.Status())

    // 记录数据
    model.NewDB().Create(&model.ActionLog{
        Name: name,
        Url: url,
        Method: method,
        Info: string(info),
        Useragent: useragent,
        Time: time.NowTimeToInt(),
        Ip: ip,
        Status: status,
    })
}
