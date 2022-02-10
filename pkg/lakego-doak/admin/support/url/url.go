package url

import (
    "strings"
    "regexp"

    "github.com/deatil/lakego-doak/lakego/helper"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/support/file"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/storage"
)

// 生成后台链接
func AdminUrl(url string) string {
    group := config.New("admin").GetString("Route.Prefix")

    return "/" + group + "/" + url
}

// 匹配链接
func MatchPath(ctx *router.Context, path string, current string) bool {
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
            if !helper.InArray(methodList, method) {
                return false
            }
        }
    }

    if helper.StringContains(path, "*") == -1 {
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

// 附件 url
func AttachmentUrl(path string, disk ...string) string {
    var url string

    if len(disk) > 0 {
        url = storage.NewWithDisk(disk[0]).Url(path)
    } else {
        url = storage.New().Url(path)
    }

    return url
}

// 附件文件地址
func AttachmentPath(path string, disk ...string) string {
    var filepath string

    if len(disk) > 0 {
        filepath = storage.NewWithDisk(disk[0]).Path(path)
    } else {
        filepath = storage.New().Path(path)
    }

    if !file.IsExist(filepath) {
        return ""
    }

    return filepath
}
