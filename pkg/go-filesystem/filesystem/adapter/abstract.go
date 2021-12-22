package adapter

import(
    "strings"
)

/**
 * 通用基类
 *
 * @create 2021-8-1
 * @author deatil
 */
type Abstract struct {
    // 前缀
    pathPrefix string

    // 分割符
    pathSeparator string
}

// 设置前缀
func (this *Abstract) SetPathPrefix(prefix string) {
    if prefix == "" {
        this.pathPrefix = ""

        return
    }

    this.pathSeparator = "/"
    this.pathPrefix = strings.TrimSuffix(prefix, "/") + this.pathSeparator
}

// 获取前缀
func (this *Abstract) GetPathPrefix() string {
    return this.pathPrefix
}

// 添加前缀
func (this *Abstract) ApplyPathPrefix(path string) string {
    return this.GetPathPrefix() + strings.TrimPrefix(path, "/")
}

// 移除前缀
func (this *Abstract) RemovePathPrefix(path string) string {
    prefix := this.GetPathPrefix()
    return strings.TrimPrefix(path, prefix)
}
