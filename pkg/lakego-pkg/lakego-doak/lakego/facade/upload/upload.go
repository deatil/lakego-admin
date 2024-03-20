package upload

import (
    "github.com/deatil/lakego-doak/lakego/upload"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/storage"
)

// 默认
var Default *upload.Upload

// 初始化
func init() {
    // 默认
    Default = New()
}

/**
 * 上传
 *
 * @create 2021-8-15
 * @author deatil
 */
func New() *upload.Upload {
    conf := config.New("admin")

    // 重命名
    rename := upload.NewRename()
    formatname := conf.GetString("Upload.Formatname")
    if formatname == "unique" {
        rename.UniqueName()
    } else if formatname == "datetime" {
        rename.DatetimeName()
    } else if formatname == "sequence" {
        rename.SequenceName()
    }

    // 文件格式
    filetypes := conf.GetStringMapString("Upload.Filetypes")

    // 文件信息
    fileinfo := upload.NewFileinfo().WithFiletypes(filetypes)

    // 文件信息2
    openFileinfo := upload.NewOpenFileinfo().WithFiletypes(filetypes)

    // 文件系统
    uploadDisk := conf.GetString("Upload.Disk")
    useStorage := storage.NewWithDisk(uploadDisk)

    // 上传文件夹
    uploadDir := conf.GetString("Upload.Directory.Image")

    // 上传
    up := upload.New().
        WithStorage(useStorage).
        WithFileinfo(fileinfo).
        WithOpenFileinfo(openFileinfo).
        WithRename(rename).
        WithDir(uploadDir)

    return up
}

