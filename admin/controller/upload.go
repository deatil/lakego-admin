package controller

import (
    "strconv"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/facade/upload"
    "lakego-admin/lakego/facade/storage"
    "lakego-admin/lakego/support/time"
    "lakego-admin/lakego/helper"
    "lakego-admin/lakego/http/controller"
    "lakego-admin/admin/auth/admin"
    "lakego-admin/admin/model"
)

/**
 * 上传
 *
 * @create 2021-8-15
 * @author deatil
 */
type UploadController struct {
    controller.BaseController
}

/**
 * 上传文件
 */
func (control *UploadController) File(ctx *gin.Context) {
    // 账号信息
    adminInfo, _ := ctx.Get("admin")
    adminId := adminInfo.(*admin.Admin).GetId()

    conf := config.New("admin")

    // 上传目录
    uploadDir := conf.GetString("Upload.Directory.File")

    // 上传文件类型
    uploadType := ctx.DefaultQuery("type", "file")
    if uploadType == "image" {
        uploadDir = conf.GetString("Upload.Directory.Image")
    } else if uploadType == "media" {
        uploadDir = conf.GetString("Upload.Directory.Media")
    }

    file, err := ctx.FormFile(conf.GetString("Upload.Field"))
    if err != nil {
        control.Error(ctx, "上传文件失败，原因：" + err.Error())
        return
    }

    up := upload.New().
        WithDir(uploadDir)

    // 文件系统
    storager := up.GetStorage()

    // 文件信息
    fileinfo := up.GetFileinfo()

    // 上传
    path := up.SaveUploadedFile(file)
    if path == "" {
        control.Error(ctx, "上传文件失败" )
        return
    }

    filePath := storager.Path(path)

    fileinfo = fileinfo.WithFilename(filePath)

    // 原始名称
    name := fileinfo.GetOriginalName()
    mimeType := fileinfo.GetMimeType()
    extension := fileinfo.GetExtension()
    size := fileinfo.GetSize()
    md5 := fileinfo.GetMd5()
    sha1 := fileinfo.GetSha1()

    // 关闭打开的文件
    fileinfo.Close()

    uploadDisk := storage.GetDefaultDisk()

    driver := "local"
    if uploadDisk != "" {
        driver = uploadDisk
    }

    // 模型
    adminModel := model.NewAdmin()
    attachmentModel := model.NewAttachment()

    attach := map[string]interface{}{}
    attachErr := attachmentModel.
        Where("md5 = ?", md5).
        First(&attach).
        Error
    if attachErr == nil && len(attach) > 0 {
        // 移除本次上传
        up.Destroy(path)

        attachUpdateErr := attachmentModel.
            Where("md5 = ?", md5).
            Updates(map[string]interface{}{
                "update_time": time.NowTime(),
            }).
            Error
        if attachUpdateErr != nil {
            control.Error(ctx, "上传文件失败")
            return
        }

        if uploadType == "image" || uploadType == "media" {
            control.SuccessWithData(ctx, "上传文件成功", gin.H{
                "id": attach["id"],
                "url": storager.Url(attach["path"].(string)),
            })
            return
        }

        control.SuccessWithData(ctx, "上传文件成功", gin.H{
            "id": attach["id"],
        })
        return
    }

    // 添加数据
    attachData := &model.Attachment{
        Name: name,
        Path: path,
        Mime: mimeType,
        Ext: extension,
        Size: strconv.FormatInt(size, 10),
        Md5: md5,
        Sha1: sha1,
        Driver: driver,
        Status: 1,
        CreateTime: int(time.NowTime()),
        AddTime: int(time.NowTime()),
        AddIp: helper.GetRequestIp(ctx),
    }
    var adminer model.Admin
    adminFindErr := adminModel.
        Where("id = ?", adminId).
        First(&adminer).
        Error
    if adminFindErr != nil {
        up.Destroy(path)
        control.Error(ctx, "上传文件失败")
        return
    }
    model.NewDB().Model(&adminer).
        Association("Attachments").
        Append(attachData)

    // 返回数据
    data := gin.H{
        "id": attachData.ID,
    }

    if uploadType == "image" || uploadType == "media" {
        url := storager.Url(path)

        data = gin.H{
            "id": attachData.ID,
            "url": url,
        }
    }

    control.SuccessWithData(ctx, "上传文件成功", data)
}
