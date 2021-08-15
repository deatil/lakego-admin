package upload

import (
    "os"
    "fmt"
    "path"
    "time"
    "regexp"
    "strconv"
    "strings"
    "net/http"

    storager "lakego-admin/lakego/storage"
    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/support/file"
    "lakego-admin/lakego/support/random"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/facade/storage"
)

/**
 * 上传
 *
 * @create 2021-8-15
 * @author deatil
 */
type Upload struct {
    // 驱动
    storage *storager.Storage

    // 文件夹 string 或者 func(*os.File) string
    directory interface{}

    // 文件
    file *os.File

    // 自定义命名 string 或者 func(*os.File) string
    name interface{}

    // 结果命名
    realname string

    // 命名方式
    generateName string

    // 权限，'private' or 'public'
    storagePermission string
}

func New() *Upload {
    return &Upload{
        name: "",
        storagePermission: "",
    }
}

// 设置使用磁盘
func (upload *Upload) WithDisk(disk string) *Upload {
    upload.storage = storage.NewWithDisk(disk)

    return upload
}

// 获取使用的驱动
func (upload *Upload) GetStorage() *storager.Storage {
    return upload.storage
}

// 设置文件夹
func (upload *Upload) WithDir(directory interface{}) *Upload {
    upload.directory = directory

    return upload
}

// 获取文件夹
func (upload *Upload) GetDir() interface{} {
    return upload.directory
}

// 设置文件流
func (upload *Upload) WithFile(file *os.File) *Upload {
    upload.file = file

    return upload
}

// 设置文件流
func (upload *Upload) GetFile() *os.File {
    return upload.file
}

// 设置文件名
func (upload *Upload) WithName(name interface{}) *Upload {
    upload.name = name

    return upload
}

// 获取文件名
func (upload *Upload) GetName() interface{} {
    return upload.name
}

// UniqueName 命名文件名
func (upload *Upload) UniqueName() *Upload {
    upload.generateName = "unique"

    return upload
}

// datetimeName 命名文件名
func (upload *Upload) DatetimeName() *Upload {
    upload.generateName = "datetime"

    return upload
}

// sequenceName 命名文件名
func (upload *Upload) SequenceName() *Upload {
    upload.generateName = "sequence"

    return upload
}

// 设置权限
func (upload *Upload) StoragePermission(permission string) *Upload {
    upload.storagePermission = permission

    return upload
}

// 设置的文件夹
func (upload *Upload) GetDirectory() string {
    if upload.directory != nil {
        switch upload.directory.(type) {
            case func(*os.File) string:
                return upload.directory.(func(*os.File) string)(upload.file)
            case string:
                return upload.directory.(string)
        }
    }

    return ""
}

// mime
func (upload *Upload) GetMimeType() string {
    // 头部字节
    buffer := make([]byte, 32)
    if _, err := upload.file.Read(buffer); err != nil {
        return ""
    }

    mimetype := http.DetectContentType(buffer)

    return mimetype
}

// 后缀
func (upload *Upload) GetExtension() string {
    s, err := upload.file.Stat()
    if err != nil {
        return ""
    }

    name := s.Name()

    return path.Ext(name)
}

// 大小
func (upload *Upload) GetSize() int64 {
    s, err := upload.file.Stat()
    if err != nil {
        return 0
    }

    return s.Size()
}

// 原始名称
func (upload *Upload) GetOriginalName() string {
    s, err := upload.file.Stat()
    if err != nil {
        return ""
    }

    name := s.Name()

    return strings.TrimSuffix(name, "." + upload.GetExtension())
}

// MD5 摘要
func (upload *Upload) GetMd5() string {
    str, err := file.Md5ForBigWithOsOpen(upload.file)
    if err != nil {
        return ""
    }

    return str
}

// sha1 摘要
func (upload *Upload) GetSha1() string {
    str, err := file.Sha1ForBigWithOsOpen(upload.file)
    if err != nil {
        return ""
    }

    return str
}

// 对外链接
func (upload *Upload) GetObjectUrl(path string) string {
    if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "//") {
        return path
    }

    return upload.storage.Url(path)
}

// 文件大类
func (upload *Upload) GetFileType() string {
    extension := upload.GetExtension()
    filetypes := config.New("admin").GetStringMapString("Upload.Filetypes")

    filetype := "other"

    for typer, pattern := range filetypes {
        if match, _ := regexp.MatchString(pattern, extension); match {
            filetype = typer
            break
        }
    }

    return filetype
}

// 最后命名
func (upload *Upload) GetRealname() string {
    return upload.realname
}

// 唯一命名
func (upload *Upload) GenerateUniqueName() string {
    name := hash.MD5(strconv.FormatInt(time.Now().Unix(), 10))

    return name + "." + upload.GetExtension()
}

// 时间命名
func (upload *Upload) GenerateDatetimeName() string {
    name := fmt.Sprintf("%s", time.Now().Format("2006-01-02 15:04:05")) + random.String(6)

    return name + "." + upload.GetExtension()
}

// sequence 命名
func (upload *Upload) GenerateSequenceName() string {
    var index int = 1
    extension := upload.GetExtension()
    original := upload.GetOriginalName()
    newFilename := fmt.Sprintf("%s_%s.%s", original, index, extension)

    for {
        if !upload.storage.Has(newFilename) {
            break
        }

        index++
        newFilename = fmt.Sprintf("%s_%s.%s", original, index, extension)
    }

    return newFilename
}

// 原始命名
func (upload *Upload) GenerateClientName() string {
    return upload.GetOriginalName() + "." + upload.GetExtension()
}

// 如果存在重命名
func (upload *Upload) RenameIfExists() {
    dir := upload.GetDirectory()
    if strings.HasSuffix(dir, "/") {
        dir = strings.TrimSuffix(dir, "/")
    }

    if upload.storage.Has(dir + "/" + upload.realname) {
        upload.realname = upload.GenerateUniqueName()
    }
}

// 获取最后存储名称
func (upload *Upload) GetStoreName() string {
    if upload.name != nil {
        switch upload.name.(type) {
            case func(*os.File) string:
                return upload.name.(func(*os.File) string)(upload.file)
            case string:
                return upload.name.(string)
        }
    }

    if upload.generateName == "unique" {
        return upload.GenerateUniqueName()
    } else if upload.generateName == "datetime" {
        return upload.GenerateDatetimeName()
    } else if upload.generateName == "sequence" {
        return upload.GenerateSequenceName()
    }

    return upload.GenerateClientName()
}

// 上传
func (upload *Upload) Upload(path string) string {
    upload.realname = upload.GetStoreName()

    upload.RenameIfExists()

    if upload.storagePermission != "" {
        return upload.storage.PutFileAs(upload.GetDirectory(), upload.file, upload.realname, map[string]interface{}{
            "visibility": upload.storagePermission,
        })
    }

    return upload.storage.PutFileAs(upload.GetDirectory(), upload.file, upload.realname)
}

// 删除
func (upload *Upload) Destroy(path string) bool {
    return upload.storage.Delete(path)
}


