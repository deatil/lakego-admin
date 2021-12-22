package filesystem

import(
    "os"

    "github.com/deatil/go-filesystem/filesystem/interfaces"
)

// new 文件管理器
func NewFile(filesystem interfaces.Fllesystem, path ...string) *File {
    fs := &File{}
    fs.filesystem = filesystem

    if len(path) > 0{
        fs.path = path[0]
    }

    return fs
}

/**
 * 文件管理扩展
 *
 * @create 2021-8-1
 * @author deatil
 */
type File struct {
    Handler
}

// 设置管理器
func (this *File) SetFilesystem(filesystem interfaces.Fllesystem) *File {
    this.filesystem = filesystem

    return this
}

// 设置目录
func (this *File) SetPath(path string) *File {
    this.path = path

    return this
}

// 存在
func (this *File) Exists() bool {
    return this.filesystem.Has(this.path)
}

// 读取
func (this *File) Read() interface{} {
    return this.filesystem.Read(this.path)
}

// 读取成文件流
func (this *File) ReadStream() *os.File {
    return this.filesystem.ReadStream(this.path)
}

// 写入字符
func (this *File) Write(content string) bool {
    return this.filesystem.Write(this.path, content)
}

// 写入文件流
func (this *File) WriteStream(resource *os.File) bool {
    return this.filesystem.WriteStream(this.path, resource)
}

// 更新字符
func (this *File) Update(content string) bool {
    return this.filesystem.Update(this.path, content)
}

// 更新文件流
func (this *File) UpdateStream(resource *os.File) bool {
    return this.filesystem.UpdateStream(this.path, resource)
}

// 导入字符
func (this *File) Put(content string) bool {
    return this.filesystem.Update(this.path, content)
}

// 导入文件流
func (this *File) PutStream(resource *os.File) bool {
    return this.filesystem.PutStream(this.path, resource)
}

// 重命名
func (this *File) Rename(newpath string) bool {
    if this.filesystem.Rename(this.path, newpath) {
        this.path = newpath

        return true
    }

    return false
}

// 复制
func (this *File) Copy(newpath string) (*File, bool) {
    if this.filesystem.Copy(this.path, newpath) {
        var file2 = &File{}
        file2.filesystem = this.filesystem
        file2.path = newpath

        return file2, true
    }

    return nil, false
}

// 时间戳
func (this *File) GetTimestamp() int64 {
    return this.filesystem.GetTimestamp(this.path)
}

// 文件类型
func (this *File) GetMimetype() string {
    return this.filesystem.GetMimetype(this.path)
}

// 权限
func (this *File) GetVisibility() string {
    return this.filesystem.GetVisibility(this.path)
}

// 数据
func (this *File) GetMetadata() map[string]interface{} {
    return this.filesystem.GetMetadata(this.path)
}

// 大小
func (this *File) GetSize() int64 {
    return this.filesystem.GetSize(this.path)
}

// 删除
func (this *File) Delete() bool {
    return this.filesystem.Delete(this.path)
}
