package stubs

import (
    "fmt"
    "embed"
    "errors"
    "strings"

    "github.com/deatil/go-datebin/datebin"
    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/path"
)

//go:embed stub
var fs embed.FS

// 构造函数
func New() Stubs {
    return Stubs{
        stubDir: "stub",
    }
}

/**
 * 脚手架
 *
 * @create 2022-12-12
 * @author deatil
 */
type Stubs struct {
    // 模板文件夹
    stubDir string
}

// 生成控制器
func (this Stubs) MakeController(name string, data map[string]string, force bool) error {
    data["datetime"] = datebin.Now().ToDatetimeString()

    srcData, err := this.readStubFile("controller")
    if err != nil {
        return err
    }

    dstFile := path.AppPath("admin/controller/" + name + ".go")

    return this.CopyFile(srcData, dstFile, data, force)
}

// 生成模型
func (this Stubs) MakeModel(name string, data map[string]string, force bool) error {
    data["datetime"] = datebin.Now().ToDatetimeString()

    srcData, err := this.readStubFile("model")
    if err != nil {
        return err
    }

    dstFile := path.AppPath("admin/model/" + name + ".go")

    return this.CopyFile(srcData, dstFile, data, force)
}

// 复制文件
func (this Stubs) CopyFile(srcData string, dst string, data map[string]string, force bool) error {
    if this.Exists(dst) && !force {
        return errors.New("[" + dst + "] 文件已经存在 !")
    }

    dstDir := filesystem.Dirname(dst)

    err := this.MakeDir(dstDir, 0755, true)
    if err != nil {
        return errors.New("[" + dstDir + "] 目录创建失败 !")
    }

    for k, v := range data {
        srcData = strings.ReplaceAll(srcData, "{" + k + "}", v)
    }

    err = filesystem.Put(dst, srcData, true)
    if err != nil {
        return errors.New("复制文件失败 !")
    }

    return nil
}

// 生成文件夹
func (this Stubs) MakeDir(path string, mode uint32, recursive bool) error {
    return filesystem.EnsureDirectoryExists(path, mode, recursive)
}

// 判断文件是否存在
func (this Stubs) Exists(path string) bool {
    return filesystem.Exists(path)
}

// 读取模板文件
func (this Stubs) readStubFile(name string) (string, error) {
    fileName := fmt.Sprintf("%s/%s.stub", this.stubDir, name)

    bytes, err := fs.ReadFile(fileName)
    if err != nil {
        return "", err
    }

    return string(bytes), nil
}
