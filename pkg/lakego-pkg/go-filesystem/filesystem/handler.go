package filesystem

/**
 * 扩展基础类
 *
 * @create 2021-8-1
 * @author deatil
 */
type Handler struct {
    filesystem *Filesystem
    path       string
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
    metadata, _ := this.filesystem.GetMetadata(this.path)
    if metadata == nil {
        return "dir"
    }

    return metadata["type"].(string)
}

// 设置文件系统
func (this *Handler) SetFilesystem(filesystem *Filesystem) any {
    this.filesystem = filesystem

    return this
}

// 获取文件系统
func (this *Handler) GetFilesystem() *Filesystem {
    return this.filesystem
}

// 设置目录
func (this *Handler) SetPath(path string) any {
    this.path = path

    return this
}

// 获取目录
func (this *Handler) GetPath() string {
    return this.path
}
