package middleware

import (
    "github.com/deatil/lakego-doak/lakego/router"
)

/**
 * 中间件
 *
 * @create 2023-4-19
 * @author deatil
 */
func NewBoot() router.HandlerFunc {
    return func(ctx *router.Context) {
        ctx.Next()
    }
}
