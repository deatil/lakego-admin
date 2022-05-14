package storage

import (
    "fmt"
    "strings"

    "github.com/deatil/lakego-filesystem/filesystem"

    "github.com/deatil/lakego-doak/lakego/path"
    "github.com/deatil/lakego-doak/lakego/color"
    "github.com/deatil/lakego-doak/lakego/command"
    "github.com/deatil/lakego-doak/lakego/facade/config"
)

/**
 * 创建软连接
 *
 * > ./main lakego:storage-link [--force]
 * > main.exe lakego:storage-link [--force]
 * > go run main.go lakego:storage-link [--force]
 *
 * @create 2022-1-27
 * @author deatil
 */
var StorageLinkCmd = &command.Command{
    Use: "lakego:storage-link",
    Short: "创建资源软连接.",
    Example: "{execfile} lakego:storage-link",
    SilenceUsage: true,
    PreRun: func(cmd *command.Command, args []string) {
    },
    Run: func(cmd *command.Command, args []string) {
        StorageLink()
    },
}

// 覆盖
var pForce bool

func init() {
    pf := StorageLinkCmd.Flags()
    pf.BoolVarP(&pForce, "force", "f", false, "是否覆盖文件")
}

// 创建公共资源软连接
func StorageLink() {
    links := config.New("filesystem").GetStringSlice("links")

    if len(links) > 0 {
        for _, link := range links {
            array := strings.Split(link, ":")
            if len(array) == 2 {
                from := path.FormatPath(array[1])
                to := path.FormatPath(array[0])

                fs := filesystem.New()

                if pForce {
                    fs.Delete(to)
                }

                fs.Link(from, to)
            }
        }
    }

    fmt.Print("\n")
    color.
        NewWithOption(
            color.BackgroundHiOption("yellow"),
            color.ForegroundOption("magenta"),
            color.BaseOption("bold"),
            color.BaseOption("blinkRapid"),
        ).
        Print("软连接创建成功")
    fmt.Print("\n")
}
