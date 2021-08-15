package upload

import (
    "lakego-admin/lakego/upload"
    "lakego-admin/lakego/facade/config"
)

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

    // 文件信息
    filetypes := conf.GetStringMapString("Upload.Filetypes")
    fileinfo := upload.NewFileinfo().WithFiletypes(filetypes)

    // 配置
    uploadDisk := conf.GetString("Upload.Disk")
    uploadDir := conf.GetString("Upload.Directory.Image")

    // 上传
    up := upload.New().
        WithRename(rename).
        WithFileinfo(fileinfo).
        WithDisk(uploadDisk).
        WithDir(uploadDir)

    return up
}

