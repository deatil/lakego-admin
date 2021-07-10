package lake

import (
    "strings"
    "regexp"

    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/config"
)

// 生成后台链接
func AdminUrl(url string) string {
    group := config.New("admin").GetString("Route.Group")

    return "/" + group + "/" + url
}

// 匹配链接
func MatchPath(ctx *gin.Context, path string, current string) bool {
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
        if len(methodList) > 0 {
            if !InArray(methodList, method) {
                return false
            }
        }
    }

    if StringContains(path, "*") == -1 {
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
