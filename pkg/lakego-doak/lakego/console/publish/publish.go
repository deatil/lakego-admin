package publish

import (
    "os"
    "sort"
    "strings"
    "path/filepath"

    "github.com/AlecAivazis/survey/v2"

    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/publish"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/filesystem"
    "github.com/deatil/lakego-doak/lakego/path"
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
        publisher := &Publisher{
            provider: "",
            tags: make([]string, 0),
        }
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
type Publisher struct {
    // 服务提供者
    provider string

    // 标签
    tags []string
}

// 运行
func (this *Publisher) Execute() {
    this.determineWhatShouldBePublished()

    if pAll || this.provider != "" || this.tags[0] != "" {
        if len(this.tags) == 0 {
            this.tags = []string{""}
        }

        for _, tag := range this.tags {
            this.PublishTag(tag)
        }
    }

    color.Greenln("\n文件推送完成")
}

// determineWhatShouldBePublished
func (this *Publisher) determineWhatShouldBePublished() {
    if pAll {
        return
    }

    this.provider = pProvider
    this.tags = []string{pTag}

    if pProvider == "" && pTag == "" {
        this.promptForProviderOrTag()
    }
}

// 选择器
// 输入接收：fmt.Scanln(&choice)
func (this *Publisher) promptForProviderOrTag() {
    choices := this.publishableChoices()

    // 选择器
    choice := ""
    prompt := &survey.Select{
        Message: "哪些是你想要推送的 provider 或者 tag 文件？",
        Options: choices,
        Default: choices[0],
        Help: "上下移动选择你需要的选项",
    }
    err := survey.AskOne(prompt, &choice)
    if err != nil {
        return
    }

    this.parseChoice(choice)
}

// 可选择列表
func (this *Publisher) publishableChoices() []string {
    var choices []string

    choices = append(choices, "能够推送的 providers 和 tags 列表")

    providers := publish.Instance().PublishableProviders()
    sort.Strings(providers[:])
    for _, v := range providers {
        choices = append(choices, "Provider: " + v)
    }

    groups := publish.Instance().PublishableGroups()
    sort.Strings(groups[:])
    for _, v2 := range groups {
        choices = append(choices, "Tag: " + v2)
    }

    return choices
}

// parseChoice
func (this *Publisher) parseChoice(choice string) {
    choices := strings.Split(choice, ": ")
    if len(choices) < 2 {
        return
    }

    typ := choices[0]
    value := choices[1]

    if typ == "Provider" {
        this.provider = value
    } else if typ == "Tag" {
        this.tags = []string{value}
    }
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
        color.Redln("不能够定位到推送资源")
    }
}

// 目录推送
func (this *Publisher) PathsToPublish(tag string) map[string]string {
    return publish.Instance().PathsToPublish(this.provider, tag)
}

// 不确定类型推送
func (this *Publisher) PublishItem(from string, to string)  {
    fs := filesystem.New()
    if fs.IsFile(from) {
        this.PublishFile(from, to)
    } else if fs.IsDirectory(from) {
        this.PublishDirectory(from, to)
    } else {
        from, _ = this.RemovePathPrefix(from)

        color.Redln("不能够定位目录: <" + from + ">")
    }
}

// 推送文件
func (this *Publisher) PublishFile(from string, to string) {
    if !this.IsExist(to) || pForce {
        this.CreateParentDirectory(filepath.Dir(to))

        filesystem.New().Copy(from, to)

        this.Status(from, to, "文件")
    }
}

// 推送文件夹
func (this *Publisher) PublishDirectory(from string, to string) {
    this.CreateParentDirectory(to)

    // 文件夹复制
    filesystem.New().CopyDirectory(from, to)

    this.Status(from, to, "文件夹")
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
    from, _ = this.RemovePathPrefix(from)
    to, _ = this.RemovePathPrefix(to)

    color.Magentaln("\n复制" + typ + " [" + from + "] 到 [" + to + "] 成功。")
}

// 判断
func (this *Publisher) IsExist(fp string) bool {
    _, err := os.Stat(fp)
    return err == nil || os.IsExist(err)
}

// 移除路径前缀
func (this *Publisher) RemovePathPrefix(pathName string) (string, error) {
    newPath, err := filepath.Abs(pathName)
    if err != nil {
        return pathName, err
    }

    basePath := path.BasePath()

    newPath = strings.TrimPrefix(newPath, basePath)
    newPath = strings.TrimPrefix(strings.Replace(newPath, "\\", "/", -1), "/")

    return newPath, nil
}
