package fllesystem

import(
    "lakego-admin/lakego/fllesystem/interfaces"
)

type Directory struct {
    Handler
}

// new 文件管理器
func NewDirectory(filesystem interfaces.Fllesystem, path ...string) *Directory {
    fs := &Directory{}
    fs.filesystem = filesystem

    if len(path) > 0{
        fs.path = path[0]
    }

    return fs
}

// 设置管理器
func (dir *Directory) SetFilesystem(filesystem interfaces.Fllesystem) *Directory {
    dir.filesystem = filesystem

    return dir
}

// 删除文件夹
func (dir *Directory) Delete() bool {
    return dir.filesystem.DeleteDir(dir.path)
}

// 列出文件
func (dir *Directory) GetContents(recursive ...bool) []map[string]interface{} {
    var rec bool
    if len(recursive) > 0 && recursive[0] {
        rec = true
    } else {
        rec = false
    }

    return dir.filesystem.ListContents(dir.path, rec)
}
