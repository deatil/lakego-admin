package upload

import (
    "io"
    "os"
    "strings"
    "mime/multipart"

    "lakego-admin/lakego/storage"
    "lakego-admin/lakego/validator"
)

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

    // 重命名
    rename *Rename

    // 文件夹
    directory string

    // 权限，'private' or 'public'
    storagePermission string
}

func New() *Upload {
    return &Upload{
        storagePermission: "",
    }
}

// 设置文件信息
func (upload *Upload) WithFileinfo(fileinfo *Fileinfo) *Upload {
    upload.fileinfo = fileinfo

    return upload
}

// 获取文件信息
func (upload *Upload) GetFileinfo() *Fileinfo {
    return upload.fileinfo
}

// 设置重命名
func (upload *Upload) WithRename(rename *Rename) *Upload {
    upload.rename = rename

    return upload
}

// 获取重命名
func (upload *Upload) GetRename() *Rename {
    return upload.rename
}

// 设置文件系统
func (upload *Upload) WithStorage(storager *storage.Storage) *Upload {
    upload.storage = storager

    return upload
}

// 获取文件系统
func (upload *Upload) GetStorage() *storage.Storage {
    return upload.storage
}

// 设置文件夹
func (upload *Upload) WithDir(directory string) *Upload {
    upload.directory = directory

    return upload
}

// 获取文件夹
func (upload *Upload) GetDir() interface{} {
    return upload.directory
}

// 设置权限
func (upload *Upload) WithPermission(permission string) *Upload {
    upload.storagePermission = permission

    return upload
}

// 设置的文件夹
func (upload *Upload) GetDirectory() string {
    if upload.directory != "" {
        return upload.directory
    }

    return ""
}

// 对外链接
func (upload *Upload) GetObjectUrl(path string) string {
    if validator.IsURL(path) {
        return path
    }

    return upload.storage.Url(path)
}

// 如果存在重命名
func (upload *Upload) IfExists(realname string) bool {
    dir := upload.GetDirectory()
    if strings.HasSuffix(dir, "/") {
        dir = strings.TrimSuffix(dir, "/")
    }

    if upload.storage.Has(dir + "/" + realname) {
        return true
    }

    return false
}

// 最后文件名
func (upload *Upload) GetRealname(name string) string {
    rename := upload.rename.
        WithFileName(name).
        WithCheckFileExistsFunc(func(newFilename string) bool {
            if upload.storage.Has(newFilename) {
                return true
            }

            return false
        })

    realname := rename.GetStoreName()

    // 如果存在
    if upload.IfExists(realname) {
        realname = rename.GenerateUniqueName()
    }

    return realname
}

// 上传文件保存
func (upload *Upload) SaveUploadedFile(file *multipart.FileHeader) string {
    // 保存名称
    name := file.Filename

    realname := upload.GetRealname(name)
    realname = strings.TrimPrefix(realname, "/")
    realname = strings.TrimSuffix(realname, "/")

    // 保存路径
    path := upload.GetDirectory()
    repath := strings.TrimSuffix(path, "/") + "/" + realname

    // 保存路径
    dst := upload.storage.Path(path)

    // 创建文件夹
    upload.fileinfo.EnsureDir(dst)

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


// 保存打开的文件
func (upload *Upload) SaveOpenedFile(file *os.File) string {
    s, err := file.Stat()
    if err != nil {
        return ""
    }

    // 文件名
    name := s.Name()

    realname := upload.GetRealname(name)

    if upload.storagePermission != "" {
        return upload.storage.PutFileAs(upload.GetDirectory(), file, realname, map[string]interface{}{
            "visibility": upload.storagePermission,
        })
    }

    return upload.storage.PutFileAs(upload.GetDirectory(), file, realname)
}

// 删除
func (upload *Upload) Destroy(path string) bool {
    return upload.storage.Delete(path)
}



