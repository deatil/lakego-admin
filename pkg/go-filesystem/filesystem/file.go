package filesystem

import(
    "io"
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
func (this *File) Read() (interface{}, error) {
    return this.filesystem.Read(this.path)
}

// 读取成文件流
func (this *File) ReadStream() (*os.File, error) {
    return this.filesystem.ReadStream(this.path)
}

// 写入字符
func (this *File) Write(content string) (bool, error) {
    return this.filesystem.Write(this.path, content)
}

// 写入文件流
func (this *File) WriteStream(resource io.Reader) (bool, error) {
    return this.filesystem.WriteStream(this.path, resource)
}

// 更新字符
func (this *File) Update(content string) (bool, error) {
    return this.filesystem.Update(this.path, content)
}

// 更新文件流
func (this *File) UpdateStream(resource io.Reader) (bool, error) {
    return this.filesystem.UpdateStream(this.path, resource)
}

// 导入字符
func (this *File) Put(content string) (bool, error) {
    return this.filesystem.Update(this.path, content)
}

// 导入文件流
func (this *File) PutStream(resource *os.File) (bool, error) {
    return this.filesystem.PutStream(this.path, resource)
}

// 重命名
func (this *File) Rename(newpath string) (bool, error) {
    if _, err := this.filesystem.Rename(this.path, newpath); err != nil {
        return false, err
    }

    this.path = newpath
    return true, nil
}

// 复制
func (this *File) Copy(newpath string) (*File, error) {
    _, err := this.filesystem.Copy(this.path, newpath)
    if err == nil {
        var file2 = &File{}
        file2.filesystem = this.filesystem
        file2.path = newpath

        return file2, nil
    }

    return nil, err
}

// 时间戳
func (this *File) GetTimestamp() (int64, error) {
    return this.filesystem.GetTimestamp(this.path)
}

// 文件类型
func (this *File) GetMimetype() (string, error) {
    return this.filesystem.GetMimetype(this.path)
}

// 权限
func (this *File) GetVisibility() (string, error) {
    return this.filesystem.GetVisibility(this.path)
}

// 数据
func (this *File) GetMetadata() (map[string]interface{}, error) {
    return this.filesystem.GetMetadata(this.path)
}

// 大小
func (this *File) GetSize() (int64, error) {
    return this.filesystem.GetSize(this.path)
}

// 删除
func (this *File) Delete() (bool, error) {
    return this.filesystem.Delete(this.path)
}
