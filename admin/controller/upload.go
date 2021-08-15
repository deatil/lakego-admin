package controller

import (
    "os"
    "github.com/gin-gonic/gin"

    "lakego-admin/lakego/upload"
    "lakego-admin/lakego/facade/config"
    "lakego-admin/lakego/http/controller"
    "lakego-admin/admin/auth/admin"
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
    adminInfo, _ := ctx.Get("admin")

    adminId := adminInfo.(*admin.Admin).GetId()

    uploadDisk := config.New("admin").GetString("Upload.Disk")
    uploadDir := config.New("admin").GetString("Upload.Directory.Image")

    file, _ := os.Open("./storage/log/22333.mp4")
    up := upload.New().
        WithDisk(uploadDisk).
        WithDir(uploadDir).
        WithFile(file).
        UniqueName()

    md5 := up.GetFileType()

    data := gin.H{
        "id": adminId,
        "md5": md5,
    }

    control.SuccessWithData(ctx, "上传文件成功", data)
}
