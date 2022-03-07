package router

import (
    "regexp"
    "strings"
    "net/url"

    "github.com/deatil/lakego-doak/lakego/support/array"
)

func FormatURL(u string) string {
    uarr := strings.Split(u, "?")
    if len(uarr) < 2 {
        return url.QueryEscape(strings.ReplaceAll(u, "/", "_"))
    }

    v, err := url.ParseQuery(uarr[1])
    if err != nil {
        return url.QueryEscape(strings.ReplaceAll(u, "/", "_"))
    }

    return url.QueryEscape(strings.ReplaceAll(uarr[0], "/", "_")) + "?" +
        strings.ReplaceAll(v.Encode(), "%7B%7B.Id%7D%7D", "{{.Id}}")
}

// 请求 IP
func GetRequestIp(ctx *Context) string {
    ip := ctx.ClientIP()

    if ip == "::1" {
        ip = "127.0.0.1"
    }

    return ip
}

// 获取 header 中指定 key 的值
func GetHeaderByName(ctx *Context, key string) string {
    return ctx.Request.Header.Get(key)
}

// 匹配链接
func MatchPath(ctx *Context, path string, current string) bool {
    requestPath := ctx.Request.URL.String()
    method := strings.ToUpper(ctx.Request.Method)

    if current == "" {
        current = requestPath
    }

    paths := strings.Split(path, ":")
    if len(paths) == 2 {
        methods := paths[0]
        path = paths[1]

        methods = strings.ToUpper(methods)
        methodList := strings.Split(methods, ",")
        if len(methodList) == 0 {
            return false
        }

        if !array.InArray(method, methodList) {
            return false
        }
    }

    if strings.Index(path, "*") == -1 {
        return path == current
    }

    path = strings.Replace(path, "*", "([0-9a-zA-Z-_,:])*", -1)
    path = strings.Replace(path, "/", "\\/", -1)

    result, _ := regexp.MatchString("^" + path, current)
    if !result {
        return false
    }

    return true
}

