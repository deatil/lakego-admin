package controller

import (
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/facade/upload"
    "lakego-admin/lakego/http/controller"
    "lakego-admin/admin/auth/admin"
    // "lakego-admin/admin/model"
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

    // 上传
    path := up.SaveUploadedFile(file)
    if path == "" {
        control.Error(ctx, "上传文件失败" )
        return
    }

    data := gin.H{
        "adminId": adminId,
        "path": path,
        "path2": file.Filename,
    }

    control.SuccessWithData(ctx, "上传文件成功", data)
}
