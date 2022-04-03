package actionlog

import (
    "strconv"
    "encoding/json"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-doak/lakego/router"

    "github.com/deatil/lakego-doak-action-log/action-log/model"
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

        recordLog(ctx)
    }
}

// 记录日志
func recordLog(ctx *router.Context) {
    path := ctx.Request.URL.Path
    raw := ctx.Request.URL.RawQuery

    method := ctx.Request.Method

    // 接收数据
    post := make(map[string]interface{})
    ctx.ShouldBind(&post)

    if raw != "" {
        path = path + "?" + raw
    }

    // 请求数据
    info, _ := json.Marshal(&post)
    useragent := ctx.Request.Header.Get("User-Agent")

    // 请求 IP
    ip := router.GetRequestIp(ctx)

    // 响应输出状态
    status := strconv.Itoa(ctx.Writer.Status())

    adminId, _ := ctx.Get("admin_id")

    name := "操作账号[-]"
    if adminId != nil {
        name = "操作账号[" + adminId.(string) + "]"
    }

    // 记录数据
    model.NewDB().Create(&model.ActionLog{
        Name: name,
        Url: path,
        Method: method,
        Info: string(info),
        Useragent: useragent,
        Time: int(datebin.NowTime()),
        Ip: ip,
        Status: status,
    })
}
