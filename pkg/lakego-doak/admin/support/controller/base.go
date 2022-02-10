package controller

import (
    "github.com/deatil/lakego-doak/lakego/router"
    httpRequest "github.com/deatil/lakego-doak/lakego/http/request"
    httpResponse "github.com/deatil/lakego-doak/lakego/http/response"

    "github.com/deatil/lakego-doak/admin/support/response"
)

/**
 * 控制器基类
 *
 * @create 2021-9-15
 * @author deatil
 */
type Base struct {
    response.Response
}

/**
 * 请求
 */
func (this *Base) Request(ctx *router.Context) *httpRequest.Request {
    return httpRequest.New().WithContext(ctx)
}

/**
 * 响应
 */
func (this *Base) response(ctx *router.Context) *httpResponse.Response {
    return httpResponse.New().WithContext(ctx)
}

