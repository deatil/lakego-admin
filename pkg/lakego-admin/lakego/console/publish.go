package console

import (
    "os"
    "fmt"
    "strings"
    "path/filepath"

    "github.com/deatil/lakego-admin/lakego/color"
    "github.com/deatil/lakego-admin/lakego/publish"
    "github.com/deatil/lakego-admin/lakego/command"
    "github.com/deatil/lakego-admin/lakego/support/file"
    "github.com/deatil/lakego-admin/lakego/support/path"
)

/**
 * 推送
 *
 * > ./main lakego:publish [--force] [--provider=providerName] [--tag=tagname]
 * > main.exe lakego:publish [--force] [--provider=providerName] [--tag=tagname]
 * > go run main.go lakego:publish [--force] [--provider=providerName] [--tag=tagname]
 *
 * @create 2022-1-3
 * @author deatil
 */
var PublishCmd = &command.Command{
    Use: "lakego:publish",
    Short: "Publish any publishable assets from pkg packages.",
    Example: "{execfile} lakego:publish",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {
    },
    Run: func(cmd *command.Command, args []string) {
        publisher := &Publisher{}
        publisher.Execute()
    },
}

// 覆盖
var pForce bool
var pAll bool
var pProvider string
var pTag string

func init() {
    pf := PublishCmd.Flags()
    pf.BoolVarP(&pForce, "force", "", false, "是否覆盖文件")
    pf.BoolVarP(&pAll, "all", "", false, "推送注册的全部数据")
    pf.StringVarP(&pProvider, "provider", "", "", "根据服务提供者推送")
    pf.StringVarP(&pTag, "tag", "", "", "根据标签推送")
}

/**
 * 推送
 *
 * @create 2022-1-3
 * @author deatil
 */
type Publisher struct {}

// 运行
func (this *Publisher) Execute() {
    if !pAll && pProvider == "" && pTag == "" {
        fmt.Println("请选择一个推送方式推送")
        return
    }

    this.PublishTag(pTag)

    fmt.Println("文件推送完成")
}

// 标签推送
func (this *Publisher) PublishTag(tag string) {
    published := false

    pathsToPublish := this.PathsToPublish(tag)

    for from, to := range pathsToPublish {
        this.PublishItem(from, to)

        published = true
    }

    if published == false {
        fmt.Println("不能够定位到推送资源")
    }
}

// 目录推送
func (this *Publisher) PathsToPublish(tag string) map[string]string {
    return publish.NewInstance().PathsToPublish(pProvider, tag)
}

// 不确定类型推送
func (this *Publisher) PublishItem(from string, to string)  {
    if file.IsFile(from) {
        this.PublishFile(from, to)
    } else if file.IsDir(from) {
        this.PublishDirectory(from, to)
    } else {
        fmt.Println("不能够定位目录: <" + color.Yellow(from) + ">")
    }
}

// 推送文件
func (this *Publisher) PublishFile(from string, to string) {
    if !this.IsExist(to) || pForce {
        this.CreateParentDirectory(filepath.Dir(to))

        file.CopyFile(from, to)

        this.Status(from, to, "File")
    }
}

// 推送文件夹
func (this *Publisher) PublishDirectory(from string, to string) {
    this.CreateParentDirectory(to)

    // 文件夹复制
    file.CopyDir(from, to)

    this.Status(from, to, "Directory")
}

// 创建文件夹
func (this *Publisher) CreateParentDirectory(directory string) error {
    if this.IsExist(directory) {
        return nil
    }

    return os.MkdirAll(directory, os.ModePerm)
}

// Status
func (this *Publisher) Status(from string, to string, typ string) {
    from, err := filepath.Abs(from)
    if err != nil {
        panic(err)
    }

    to, err2 := filepath.Abs(to)
    if err2 != nil {
        panic(err2)
    }

    from = strings.TrimPrefix(from, path.BasePath())
    to = strings.TrimPrefix(to, path.BasePath())

    fmt.Println("Copied " + color.Green(typ) + " [" + color.Yellow(from) + "] To [" + color.Yellow(to) + "]")
}

// 判断
func (this *Publisher) IsExist(fp string) bool {
    _, err := os.Stat(fp)
    return err == nil || os.IsExist(err)
}
