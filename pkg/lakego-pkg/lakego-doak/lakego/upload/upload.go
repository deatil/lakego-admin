package upload

import (
    "os"
    "io"
    "strings"
    "mime/multipart"
    
    "github.com/deatil/lakego-filesystem/filesystem"
    "github.com/deatil/lakego-doak/lakego/storage"
    "github.com/deatil/lakego-doak/lakego/validator"
)

// 上传
func New() *Upload {
    return &Upload{
        storagePermission: "",
    }
}

/**
 * 上传
 *
 * @create 2021-8-15
 * @author deatil
 */
type Upload struct {
    // 驱动
    storage *storage.Storage

    // 文件信息
    fileinfo *Fileinfo

    // 文件信息
    openFileinfo *OpenFileinfo

    // 重命名
    rename *Rename

    // 文件夹
    directory string

    // 权限，'private' or 'public'
    storagePermission string
}

// 设置文件信息
func (this *Upload) WithFileinfo(fileinfo *Fileinfo) *Upload {
    this.fileinfo = fileinfo

    return this
}

// 获取文件信息
func (this *Upload) GetFileinfo() *Fileinfo {
    return this.fileinfo
}

// 设置文件信息2
func (this *Upload) WithOpenFileinfo(fileinfo *OpenFileinfo) *Upload {
    this.openFileinfo = fileinfo

    return this
}

// 获取文件信息2
func (this *Upload) GetOpenFileinfo() *OpenFileinfo {
    return this.openFileinfo
}

// 设置重命名
func (this *Upload) WithRename(rename *Rename) *Upload {
    this.rename = rename

    return this
}

// 获取重命名
func (this *Upload) GetRename() *Rename {
    return this.rename
}

// 设置文件系统
func (this *Upload) WithStorage(storager *storage.Storage) *Upload {
    this.storage = storager

    return this
}

// 获取文件系统
func (this *Upload) GetStorage() *storage.Storage {
    return this.storage
}

// 设置文件夹
func (this *Upload) WithDir(directory string) *Upload {
    this.directory = directory

    return this
}

// 获取文件夹
func (this *Upload) GetDir() interface{} {
    return this.directory
}

// 设置权限
func (this *Upload) WithPermission(permission string) *Upload {
    this.storagePermission = permission

    return this
}

// 设置的文件夹
func (this *Upload) GetDirectory() string {
    if this.directory != "" {
        return this.directory
    }

    return ""
}

// 对外链接
func (this *Upload) GetObjectUrl(path string) string {
    if validator.IsURL(path) {
        return path
    }

    return this.storage.Url(path)
}

// 如果存在重命名
func (this *Upload) IfExists(realname string) bool {
    dir := this.GetDirectory()
    if strings.HasSuffix(dir, "/") {
        dir = strings.TrimSuffix(dir, "/")
    }

    if this.storage.Has(dir + "/" + realname) {
        return true
    }

    return false
}

// 最后文件名
func (this *Upload) GetRealname(name string) string {
    rename := this.rename.
        WithFileName(name).
        WithCheckFileExistsFunc(func(newFilename string) bool {
            if this.storage.Has(newFilename) {
                return true
            }

            return false
        })

    realname := rename.GetStoreName()

    // 如果存在
    if this.IfExists(realname) {
        realname = rename.GenerateUniqueName()
    }

    return realname
}

// 上传文件保存
func (this *Upload) SaveUploadedFile(file *multipart.FileHeader) string {
    // 保存名称
    name := file.Filename

    realname := this.GetRealname(name)
    realname = strings.TrimPrefix(realname, "/")
    realname = strings.TrimSuffix(realname, "/")

    // 保存路径
    path := this.GetDirectory()
    repath := strings.TrimSuffix(path, "/") + "/" + realname

    // 保存路径
    dst := this.storage.Path(path)

    // 创建文件夹
    this.EnsureDir(dst)

    // 目录
    dst = strings.TrimSuffix(dst, "/") + "/" + realname

    src, err := file.Open()
    if err != nil {
        return ""
    }
    defer src.Close()

    out, err := os.Create(dst)
    if err != nil {
        return ""
    }
    defer out.Close()

    _, err = io.Copy(out, src)
    if err != nil {
        return ""
    }

    return repath
}

// 保存上传的文件
func (this *Upload) SaveFile(file *multipart.FileHeader) string {
    // 打开上传文件
    uploadFile, err := file.Open()
    if err != nil {
        return ""
    }
    defer uploadFile.Close()

    // 保存名称
    name := file.Filename

    realname := this.GetRealname(name)

    if this.storagePermission != "" {
        path, _ := this.storage.PutFileAs(this.GetDirectory(), uploadFile, realname, map[string]interface{}{
            "visibility": this.storagePermission,
        })
        return path
    }

    path, _ := this.storage.PutFileAs(this.GetDirectory(), uploadFile, realname)
    return path
}

// 保存打开的文件
func (this *Upload) SaveOpenedFile(file *os.File) string {
    s, err := file.Stat()
    if err != nil {
        return ""
    }

    // 文件名
    name := s.Name()

    realname := this.GetRealname(name)

    if this.storagePermission != "" {
        path, _ := this.storage.PutFileAs(this.GetDirectory(), file, realname, map[string]interface{}{
            "visibility": this.storagePermission,
        })
        return path
    }

    path, _ := this.storage.PutFileAs(this.GetDirectory(), file, realname)
    return path
}

// 保存文本信息
func (this *Upload) SaveContents(contents string, name string) string {
    realname := this.GetRealname(name)

    if this.storagePermission != "" {
        path, _ := this.storage.PutContentsAs(this.GetDirectory(), contents, realname, map[string]interface{}{
            "visibility": this.storagePermission,
        })
        return path
    }

    path, _ :=  this.storage.PutContentsAs(this.GetDirectory(), contents, realname)
    return path
}

// 删除
func (this *Upload) Destroy(path string) bool {
    _, err := this.storage.Delete(path)
    if err != nil {
        return false
    }

    return true
}

// 创建文件夹
func (this *Upload) EnsureDir(path string) bool {
    err := filesystem.New().MakeDirectory(path, 0666)
    if err != nil {
        return false
    }

    return true
}
