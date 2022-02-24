package url

import (
    "github.com/deatil/lakego-doak/lakego/tool"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/storage"
)

// 匹配链接
func MatchPath(ctx *router.Context, path string, current string) bool {
    return tool.MatchPath(ctx, path, current)
}

// 生成后台链接
func AdminUrl(url string) string {
    group := config.New("admin").GetString("Route.Prefix")

    return "/" + group + "/" + url
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

    return filepath
}
