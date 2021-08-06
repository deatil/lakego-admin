package fllesystem

import(
    "os"

    "lakego-admin/lakego/fllesystem/interfaces"
)

type File struct {
    Handler
}

// new 文件管理器
func NewFile(filesystem interfaces.Fllesystem, path ...string) *File {
    fs := &File{}
    fs.filesystem = filesystem

    if len(path) > 0{
        fs.path = path[0]
    }

    return fs
}

// 设置管理器
func (file *File) SetFilesystem(filesystem interfaces.Fllesystem) *File {
    file.filesystem = filesystem

    return file
}

// 存在
func (file *File) Exists() bool {
    return file.filesystem.Has(file.path)
}

// 读取
func (file *File) Read() interface{} {
    return file.filesystem.Read(file.path)
}

// 读取成文件流
func (file *File) ReadStream() *os.File {
    return file.filesystem.ReadStream(file.path)
}

// 写入字符
func (file *File) Write(content string) bool {
    return file.filesystem.Write(file.path, content)
}

// 写入文件流
func (file *File) WriteStream(resource *os.File) bool {
    return file.filesystem.WriteStream(file.path, resource)
}

// 更新字符
func (file *File) Update(content string) bool {
    return file.filesystem.Update(file.path, content)
}

// 更新文件流
func (file *File) UpdateStream(resource *os.File) bool {
    return file.filesystem.UpdateStream(file.path, resource)
}

// 导入字符
func (file *File) Put(content string) bool {
    return file.filesystem.Update(file.path, content)
}

// 导入文件流
func (file *File) PutStream(resource *os.File) bool {
    return file.filesystem.PutStream(file.path, resource)
}

// 重命名
func (file *File) Rename(newpath string) bool {
    if file.filesystem.Rename(file.path, newpath) {
        file.path = newpath

        return true
    }

    return false
}

// 复制
func (file *File) Copy(newpath string) (*File, bool) {
    if file.filesystem.Copy(file.path, newpath) {
        var file2 = &File{}
        file2.filesystem = file.filesystem
        file2.path = newpath

        return file2, true
    }

    return nil, false
}

// 时间戳
func (file *File) GetTimestamp() int64 {
    return file.filesystem.GetTimestamp(file.path)
}

// 文件类型
func (file *File) GetMimetype() string {
    return file.filesystem.GetMimetype(file.path)
}

// 权限
func (file *File) GetVisibility() string {
    return file.filesystem.GetVisibility(file.path)
}

// 数据
func (file *File) GetMetadata() map[string]interface{} {
    return file.filesystem.GetMetadata(file.path)
}

// 大小
func (file *File) GetSize() int64 {
    return file.filesystem.GetSize(file.path)
}

// 删除
func (file *File) Delete() bool {
    return file.filesystem.Delete(file.path)
}
