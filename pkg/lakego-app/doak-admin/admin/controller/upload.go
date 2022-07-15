package controller

import (
    "strconv"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-doak/lakego/router"
    "github.com/deatil/lakego-doak/lakego/facade/config"
    "github.com/deatil/lakego-doak/lakego/facade/upload"
    "github.com/deatil/lakego-doak/lakego/facade/storage"

    "github.com/deatil/lakego-doak-admin/admin/auth/admin"
    "github.com/deatil/lakego-doak-admin/admin/model"
)

/**
 * 上传
 *
 * @create 2021-8-15
 * @author deatil
 */
type Upload struct {
    Base
}

// 上传文件
// @Summary 上传文件
// @Description 上传文件
// @Tags 上传
// @Accept  application/json
// @Produce application/json
// @Param type query    string false "文件类型，可选数据：image | media | file。默认：file"
// @Param file formData string true  "文件数据"
// @Success 200 {string} json "{"success": true, "code": 0, "message": "string", "data": ""}"
// @Router /upload/file [post]
// @Security Bearer
// @x-lakego {"slug": "lakego-admin.upload.file"}
func (this *Upload) File(ctx *router.Context) {
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
        this.Error(ctx, "上传文件失败，原因：" + err.Error())
        return
    }

    // 设置目录
    up := upload.New().WithDir(uploadDir)

    // 文件信息
    fileinfo := up.GetFileinfo()

    // 设置文件流
    fileinfo = fileinfo.WithFile(file)

    // 原始名称
    name := fileinfo.GetOriginalFilename()
    mimeType := fileinfo.GetMimeType()
    extension := fileinfo.GetExtension()
    size := fileinfo.GetSize()
    md5 := fileinfo.GetMd5()
    sha1 := fileinfo.GetSha1()

    // 关闭打开的文件
    fileinfo.CloseFile()

    uploadDisk := storage.GetDefaultDisk()

    driver := "local"
    if uploadDisk != "" {
        driver = uploadDisk
    }

    // 文件系统
    storager := up.GetStorage()

    // 模型
    adminModel := model.NewAdmin()
    attachmentModel := model.NewAttachment()

    attach := map[string]any{}
    attachErr := attachmentModel.
        Where("md5 = ?", md5).
        First(&attach).
        Error
    if attachErr == nil && len(attach) > 0 {
        attachUpdateErr := attachmentModel.
            Where("md5 = ?", md5).
            Updates(map[string]any{
                "update_time": datebin.NowTime(),
            }).
            Error
        if attachUpdateErr != nil {
            this.Error(ctx, "上传文件失败")
            return
        }

        if uploadType == "image" || uploadType == "media" {
            this.SuccessWithData(ctx, "上传文件成功", router.H{
                "id": attach["id"],
                "url": storager.Url(attach["path"].(string)),
            })
            return
        }

        this.SuccessWithData(ctx, "上传文件成功", router.H{
            "id": attach["id"],
        })
        return
    }

    // 获取当前账号信息
    var adminer model.Admin
    adminFindErr := adminModel.
        Where("id = ?", adminId).
        First(&adminer).
        Error
    if adminFindErr != nil {
        this.Error(ctx, "上传文件失败")
        return
    }

    // 上传
    path := up.SaveFile(file)
    if path == "" {
        this.Error(ctx, "上传文件失败" )
        return
    }

    // 添加数据
    attachData := &model.Attachment{
        Name: name,
        Path: path,
        Mime: mimeType,
        Extension: extension,
        Size: strconv.FormatInt(size, 10),
        Md5: md5,
        Sha1: sha1,
        Disk: driver,
        Status: 1,
        CreateTime: int(datebin.NowTime()),
        AddTime: int(datebin.NowTime()),
        AddIp: router.GetRequestIp(ctx),
    }
    addError := model.NewDB().
        Model(&adminer).
        Association("Attachments").
        Append(attachData)
    // 添加数据库失败
    if addError != nil {
        up.Destroy(path)
        this.Error(ctx, "上传文件失败")
        return
    }

    // 返回数据
    data := router.H{
        "id": attachData.ID,
    }

    if uploadType == "image" || uploadType == "media" {
        url := storager.Url(path)

        data = router.H{
            "id": attachData.ID,
            "url": url,
        }
    }

    this.SuccessWithData(ctx, "上传文件成功", data)
}
