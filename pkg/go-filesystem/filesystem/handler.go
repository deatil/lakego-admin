package filesystem

import(
    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

/**
 * 扩展基础类
 *
 * @create 2021-8-1
 * @author deatil
 */
type Handler struct {
    filesystem interfaces.Fllesystem
    path string
}

// 是否为文件夹
func (this *Handler) IsDir() bool {
    return this.GetType() == "dir"
}

// 是否为文件
func (this *Handler) IsFile() bool {
    return this.GetType() == "file"
}

// 类型
func (this *Handler) GetType() string {
    metadata := this.filesystem.GetMetadata(this.path)

    if metadata == nil {
        return "dir"
    }

    return metadata["type"].(string)
}

// 设置文件系统
func (this *Handler) SetFilesystem(filesystem interfaces.Fllesystem) interface{} {
    this.filesystem = filesystem

    return this
}

// 获取文件系统
func (this *Handler) GetFilesystem() interfaces.Fllesystem {
    return this.filesystem
}

// 设置目录
func (this *Handler) SetPath(path string) interface{} {
    this.path = path

    return this
}

// 获取目录
func (this *Handler) GetPath() string {
    return this.path
}
