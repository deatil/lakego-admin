package upload

import (
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
    storage *storage.Storage

    // 文件夹 string 或者 func(*storage.Storage) string
    directory interface{}

    // 自定义命名 string 或者 func(*storage.Storage) string
    name interface{}

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

// 设置文件夹
func (upload *Upload) WithDir(directory interface{}) *Upload {
    upload.directory = directory

    return upload
}

// 获取文件夹
func (upload *Upload) GetDir() interface{} {
    return upload.directory
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

// 获取使用的驱动
func (upload *Upload) GetStorage() *storage.Storage {
    return upload.storage
}

// 获取最后存储名称
func (upload *Upload) GetStoreName(file string) string {

    return upload.storage
}


